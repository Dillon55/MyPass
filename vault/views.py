from django.shortcuts import render, redirect
from .forms import RegistrationForm, LoginForm, PasswordForm, GroupForm, TwoFactorForm
import bcrypt
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import VaultUser
from .db_connection import get_passwords_collection, get_users_collection
from django.shortcuts import redirect, render
from django.contrib import messages
from django.shortcuts import redirect, render
from django.http import JsonResponse
from django.contrib import messages
import json
from .models import VaultUser  #Ensure VaultUser handles password verification
import logging
import secrets
import string
import traceback



def welcome(request):
    return render(request, 'welcome.html')


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            vault_user = VaultUser()

            #Call the create_user method with the required arguments
            result = vault_user.create_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                password=form.cleaned_data['password']
            )

            if result['success']:
                messages.success(request, "Registration successful. You can now log in.")
                return redirect('login')
            else:
                form.add_error(None, result['error'])

    else:
        form = RegistrationForm()

    return render(request, 'register.html', {'form': form})


def login(request):
    #Check if the user is in the 2FA verification phase
    if 'awaiting_2fa' in request.session:
        username = request.session.get('awaiting_2fa')
        
        if request.method == 'POST':
            form = TwoFactorForm(request.POST)
            if form.is_valid():
                code = form.cleaned_data['code']
                
                vault_user = VaultUser()
                result = vault_user.verify_2fa_code(username, code)
                
                if result['success']:
                    #2FA verification successful, complete login
                    request.session.pop('awaiting_2fa', None)
                    request.session['username'] = username
                    return redirect('dashboard')
                else:
                    #Invalid or expired code
                    form.add_error('code', result['error'])
        else:
            #GET request for the 2FA verification page
            form = TwoFactorForm()
        
        return render(request, 'verify_2fa.html', {'form': form})
    
    #Normal login flow
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            vault_user = VaultUser()
            user = vault_user.authenticate(
                form.cleaned_data['username'], form.cleaned_data['password']
            )

            if user:
                username = user['username']
                
                #Send 2FA verification code to user's email
                result = vault_user.send_2fa_email(username)
                if result['success']:
                    #Store username in session and redirect to 2FA verification page
                    request.session['awaiting_2fa'] = username
                    return redirect('verify_2fa')  #We'll create this URL
                else:
                    #Failed to send email
                    form.add_error(None, f"Failed to send verification code: {result.get('error', 'Unknown error')}")
            else:
                #Invalid credentials
                if vault_user.get_user_by_username(form.cleaned_data['username']):
                    form.add_error('password', "Incorrect password.")
                else:
                    form.add_error('username', "Username does not exist.")
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})



def dashboard_view(request):
    if 'username' not in request.session:
        return redirect('login')
    
    username = request.session['username']
    users_collection = get_users_collection()
    user = users_collection.find_one({'username': username})
    if not user:
        return redirect('login')
    
    groups = user.get('groups', [])
    passwords_collection = get_passwords_collection()
    
    #Convert _id to string for each password
    user_passwords = []
    for password in passwords_collection.find({'username': username}):
        #Convert _id to string and add as 'id'
        password['id'] = str(password['_id'])
        user_passwords.append(password)
    
    for group in groups:
        group_passwords = []
        for password_id in group.get('passwords', []):
            password = passwords_collection.find_one({'_id': password_id})
            if password:
                #Convert _id to string and add as 'id'
                password['id'] = str(password['_id'])
                group_passwords.append(password)
        group['passwords'] = group_passwords
    
    return render(request, 'dashboard.html', 
                  {'passwords': user_passwords, 
                   'groups': groups, 
                   'username': username})

    

def generate_password(request):
    password = None
    if request.method == "POST":
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(16))
    return render(request, 'generate_password.html', {'password': password})


def add_password(request):
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            group_id = request.POST.get('group_id', None) 
            #Get the account password
            account_password = form.cleaned_data.get('account_password')
            #Fetch the user's stored password
            users_collection = get_users_collection()
            user = users_collection.find_one({'username': request.session.get('username')})
         


            vault_user = VaultUser()
            result = vault_user.add_password(
                username=request.session.get('username'),
                service_name=form.cleaned_data['service_name'],
                username_name=form.cleaned_data['username_name'],
                password=form.cleaned_data['password'],
                master_password=account_password,  #Pass account password for encryption
                group_id=group_id
            )

            if result['success']:
                return redirect('dashboard')
            else:
                form.add_error(None, result['error'])
                
    else:
        users_collection = get_users_collection()
        user = users_collection.find_one({'username': request.session.get('username')})
        groups = user.get('groups', [])

        form = PasswordForm()

    return render(request, 'add_password.html', {'form': form, 'groups': groups})



logger = logging.getLogger(__name__)



def edit_password(request, password_id):
    if 'username' not in request.session:
        return redirect('login')

    username = request.session.get('username')
    passwords_collection = get_passwords_collection()
    original_password_entry = passwords_collection.find_one({'_id': str(password_id)})

    if not original_password_entry or original_password_entry.get('username') != username:
        messages.error(request, "Password not found or you don't have permission to edit it")
        return redirect('dashboard')

    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == 'POST':
        new_service_name = request.POST.get('service_name')
        new_username_name = request.POST.get('username_name')
        new_password = request.POST.get('password')
        account_password = request.POST.get('account_password')

        password_change = new_password and new_password != "******"

        vault_user = VaultUser()
        user = vault_user.get_user_by_username(username)

        if password_change:
            if not account_password:
                error_msg = 'Account password required'
                if is_ajax:
                    return JsonResponse({'success': False, 'error': error_msg})
                else:
                    return render(request, 'enter_password.html', {
                        'password_id': password_id,
                        'service_name': new_service_name,
                        'username_name': new_username_name,
                        'new_password': new_password
                    })

            if not user or not bcrypt.checkpw(account_password.encode('utf-8'), user.get('password')):
                error_msg = 'Incorrect password.'
                if is_ajax:
                    return JsonResponse({'success': False, 'error': error_msg})
                else:
                    messages.error(request, error_msg)
                    return redirect('dashboard')

        # Call the model method to update password details
        result = vault_user.edit_password(
            username=username,
            password_id=password_id,
            new_service_name=new_service_name,
            new_username_name=new_username_name,
            new_password=new_password,
            master_password=account_password if password_change else None
        )

        if result.get('success'):
            if is_ajax:
                return JsonResponse({'success': True, 'message': result.get('message', 'Password updated successfully.')})
            else:
                messages.success(request, result.get('message', 'Password updated successfully.'))
                return redirect('dashboard')
        else:
            error_msg = result.get('error', 'Failed to update password.')
            if is_ajax:
                return JsonResponse({'success': False, 'error': error_msg})
            else:
                messages.error(request, error_msg)
                return redirect('dashboard')

    return render(request, 'edit_password.html', {'password': original_password_entry})


def create_group(request):
    if 'username' not in request.session:
        return redirect('login')

    username = request.session['username']
    if request.method == 'POST':
        form = GroupForm(request.POST)
        if form.is_valid():
            vault_user = VaultUser()
            result = vault_user.create_group(username, form.cleaned_data['name'])

            if result['success']:
                return redirect('dashboard')
            else:
                form.add_error(None, result['error'])
    else:
        form = GroupForm()

    return render(request, 'create_group.html', {'form': form})

@csrf_exempt
def delete_password(request):
    if request.method == 'POST':
        try:
            #Parse the request body
            body = json.loads(request.body.decode('utf-8'))
            
            #Extract required parameters
            _id = body.get('_id')
            account_password = body.get('account_password')
            
            #Comprehensive parameter validation
            if not _id:
                return JsonResponse({
                    'success': False, 
                    'error': 'Missing password ID.',
                    'debug_info': {
                        'received_keys': list(body.keys()),
                        'raw_body': body
                    }
                }, status=400)
            
            if not account_password:
                return JsonResponse({
                    'success': False, 
                    'error': 'Account password is required.',
                }, status=400)
            
            #Check user session
            username = request.session.get('username')
            if not username:
                return JsonResponse({
                    'success': False, 
                    'error': 'User not logged in.'
                }, status=401)
            
            #Verify user exists and account password is correct
            vault_user = VaultUser()
            user = vault_user.get_user_by_username(username)
            
            if not user:
                return JsonResponse({
                    'success': False, 
                    'error': 'User account not found.'
                }, status=404)
            
            #Verify account password
            stored_password = user.get('password')
            if not bcrypt.checkpw(account_password.encode('utf-8'), stored_password):
                return JsonResponse({
                    'success': False, 
                    'error': 'Incorrect account password.'
                }, status=401)
            
            #Attempt to delete the password
            delete_result = vault_user.delete_password(username, _id)
            
            #Handle delete result
            if delete_result['success']:
                return JsonResponse({
                    'success': True, 
                    'message': 'Password deleted successfully.'
                })
            else:
                return JsonResponse({
                    'success': False, 
                    'error': delete_result.get('error', 'Failed to delete password')
                }, status=400)
        
        except json.JSONDecodeError:
            #Handle JSON parsing errors
            return JsonResponse({
                'success': False, 
                'error': 'Invalid JSON in request body.'
            }, status=400)
        
        except Exception as e:
            #Catch-all for unexpected errors
            logger.error(f"Unexpected error in delete_password: {e}")
            import traceback
            traceback.print_exc()
            
            return JsonResponse({
                'success': False, 
                'error': 'An unexpected error occurred.',
                'details': str(e)
            }, status=500)
    
    #Handle non-POST requests
    return JsonResponse({
        'success': False, 
        'error': 'Method not allowed.'
    }, status=405)


@csrf_exempt
def delete_group(request):
    if request.method == 'POST':
        try:
            #Parse the request body
            body = json.loads(request.body.decode('utf-8'))
            
            #Extract required parameters
            group_id = body.get('group_id')
            account_password = body.get('account_password')
            
            #Validate parameters
            if not group_id:
                return JsonResponse({
                    'success': False, 
                    'error': 'Missing group ID.'
                }, status=400)
            
            if not account_password:
                return JsonResponse({
                    'success': False, 
                    'error': 'Account password is required.'
                }, status=400)
            
            #Check user session
            username = request.session.get('username')
            if not username:
                return JsonResponse({
                    'success': False, 
                    'error': 'User not logged in.'
                }, status=401)
            
            #Verify user exists and account password is correct
            vault_user = VaultUser()
            user = vault_user.get_user_by_username(username)
            
            if not user:
                return JsonResponse({
                    'success': False, 
                    'error': 'User account not found.'
                }, status=404)
            
            #Verify account password
            stored_password = user.get('password')
            if not bcrypt.checkpw(account_password.encode('utf-8'), stored_password):
                return JsonResponse({
                    'success': False, 
                    'error': 'Incorrect account password.'
                }, status=401)
            
            #Attempt to delete the group
            delete_result = vault_user.delete_group(username, group_id)
            
            #Handle delete result
            if delete_result['success']:
                return JsonResponse({
                    'success': True, 
                    'message': 'Group deleted successfully.'
                })
            else:
                return JsonResponse({
                    'success': False, 
                    'error': delete_result.get('error', 'Failed to delete group')
                }, status=400)
        
        except json.JSONDecodeError:
            #Handle JSON parsing errors
            return JsonResponse({
                'success': False, 
                'error': 'Invalid JSON in request body.'
            }, status=400)
        
        except Exception as e:
            #Catch-all for unexpected errors
            logger.error(f"Unexpected error in delete_group: {e}")
            import traceback
            traceback.print_exc()
            
            return JsonResponse({
                'success': False, 
                'error': 'An unexpected error occurred.',
                'details': str(e)
            }, status=500)
    
    #Handle non-POST requests
    return JsonResponse({
        'success': False, 
        'error': 'Method not allowed.'
    }, status=405)
@csrf_exempt  #Use only if necessary; better to rely on CSRF tokens
def verify_account_password(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body.decode('utf-8'))
            account_password = body.get('account_password')

            #Fetch the stored user password
            username = request.session.get('username')
            if not username:
                return JsonResponse({'success': False, 'error': 'User not logged in.'}, status=400)

            user = VaultUser().get_user_by_username(username)
            if not user:
                return JsonResponse({'success': False, 'error': 'User not found.'}, status=404)

            stored_password = user['password']  #Hashed password (should already be bytes)
            print(f"DEBUG: Stored Password Hash (Bytes): {stored_password}")  #Debug log
            print(f"DEBUG: Entered Password (Raw): {account_password}")  #Debug log

            #Ensure stored_password is in bytes format
            if isinstance(stored_password, str):  
                stored_password = stored_password.encode('utf-8')  #Convert to bytes if it's a string

            #Verify password
            if bcrypt.checkpw(account_password.encode('utf-8'), stored_password):
                print("DEBUG: Password verified successfully.")  #Debug log
                return JsonResponse({'success': True, 'message': 'Password verified.'})
            else:
                print("ERROR: Incorrect password.")  #Debug log
                return JsonResponse({'success': False, 'error': 'Incorrect password.'}, status=401)

        except Exception as e:
            print(f"ERROR: {str(e)}")  #Debug log
            return JsonResponse({'success': False, 'error': 'An error occurred.', 'details': str(e)}, status=500)

    return JsonResponse({'success': False, 'error': 'Invalid request method.'}, status=405)

def edit_group(request, group_id):
    if 'username' not in request.session:
        return redirect('login')

    username = request.session['username']
    users_collection = get_users_collection()

    # Fetch user and group data
    user = users_collection.find_one({'username': username})
    if not user:
        return redirect('dashboard')  # User not found

    group = next((group for group in user.get('groups', []) if group['group_id'] == group_id), None)
    if not group:
        return redirect('dashboard')  # Group not found

    group_password_ids = group.get('passwords', [])

    passwords_collection = get_passwords_collection()
    group_password_data = []

    for password_id in group_password_ids:
        password = passwords_collection.find_one({'_id': password_id})
        if password:
            group_password_data.append({
                'password_id': str(password['_id']),
                'service_name': password.get('service_name'),
                'username_name': password.get('username_name'),
                'password': password.get('password')
            })

    user_passwords = [
        {**password, 'id': str(password['_id'])} for password in passwords_collection.find({'username': username})
    ]

    if request.method == 'POST':
        remove_password_ids = request.POST.getlist('remove_passwords')
        add_password_ids = request.POST.getlist('add_passwords')

        # Remove selected passwords
        updated_group_password_ids = [pid for pid in group_password_ids if pid not in remove_password_ids]

        # Add new passwords if not already present
        for pid in add_password_ids:
            if pid not in updated_group_password_ids:
                updated_group_password_ids.append(pid)

        # Use the model method to update the group passwords
        result = VaultUser.update_group_passwords(username, group_id, updated_group_password_ids)

        if result.get('success'):
            messages.success(request, "Group passwords updated successfully.")
        else:
            messages.error(request, result.get('error', 'Failed to update group passwords.'))

        return redirect('dashboard')

    return render(request, 'edit_group.html', {
        'group': group,
        'group_passwords': group_password_data,
        'user_passwords': user_passwords,
        'group_password_ids': group_password_ids,
        'group_id': group_id
    })



@csrf_exempt
def decrypt_password(request):
    if request.method == "POST":
        try:
            #- Parse JSON data
            data = json.loads(request.body)
            encrypted_password = data.get("encrypted_password")
            account_password = data.get("account_password")

            #- Validate inputs
            if not encrypted_password:
                return JsonResponse({"success": False, "error": "Missing encrypted password"}, status=400)
            if not account_password:
                return JsonResponse({"success": False, "error": "Missing account password"}, status=400)

            #Get username from session
            username = request.session.get('username')
            if not username:
                return JsonResponse({"success": False, "error": "User not logged in"}, status=401)

            #Create vault user instance
            vault_user = VaultUser()
            
            #Verify the account password first
            user = vault_user.get_user_by_username(username)
            if not user:
                return JsonResponse({"success": False, "error": "User not found"}, status=404)
                
          
            stored_password = user.get('password')
            if not bcrypt.checkpw(account_password.encode('utf-8'), stored_password):
                return JsonResponse({"success": False, "error": "Incorrect account password"}, status=401)
            
            #Attempt to decrypt
            try:
                decrypted_password = vault_user.decrypt_password(encrypted_password, account_password)
                return JsonResponse({"success": True, "decrypted_password": decrypted_password})
            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")
                return JsonResponse({
                    "success": False, 
                    "error": "Incorrect password or corrupted data. Please try again."
                }, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"success": False, "error": "Invalid JSON data"}, status=400)
        except Exception as e:
            logger.error(f"General error in decrypt_password: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return JsonResponse({"success": False, "error": "Server error occurred"}, status=500)

    return JsonResponse({"success": False, "error": "Method not allowed"}, status=405)



def verify_2fa(request):
    #Ensure user is awaiting 2FA verification
    if 'awaiting_2fa' not in request.session:
        return redirect('login')
    
    username = request.session.get('awaiting_2fa')
    
    if request.method == 'POST':
        form = TwoFactorForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['code']
            
            vault_user = VaultUser()
            result = vault_user.verify_2fa_code(username, code)
            
            if result['success']:
                #2FA verification successful, complete login
                request.session.pop('awaiting_2fa', None)
                request.session['username'] = username
                return redirect('dashboard')
            else:
                #Invalid or expired code
                form.add_error('code', result['error'])
    else:
        form = TwoFactorForm()
    
    return render(request, 'verify_2fa.html', {'form': form})

def resend_2fa_code(request):
    """Resend 2FA verification code"""
    if 'awaiting_2fa' not in request.session:
        return redirect('login')
    
    username = request.session.get('awaiting_2fa')
    
    vault_user = VaultUser()
    result = vault_user.send_2fa_email(username)
    
    if result['success']:
        messages.success(request, "Verification code has been resent to your email.")
    else:
        messages.error(request, f"Failed to resend code: {result.get('error', 'Unknown error')}")
    
    return redirect('verify_2fa')


def cancel_2fa(request):
    """Cancel 2FA verification and return to login page"""
    #Clear the 2FA session variable
    if 'awaiting_2fa' in request.session:
        del request.session['awaiting_2fa']
        request.session.modified = True  #Ensure the session is saved
    
    #Force a session save to ensure changes are committed
    request.session.save()
    
    return redirect('login')

def user_logout(request):
    request.session.flush()
    return redirect('welcome')