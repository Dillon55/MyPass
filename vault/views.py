from django.shortcuts import render, redirect
from .forms import RegistrationForm, LoginForm, PasswordForm, GroupForm
import bcrypt
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from .models import VaultUser
from .db_connection import get_passwords_collection, get_users_collection
from uuid import uuid4



def welcome(request):
    return render(request, 'welcome.html')


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            vault_user = VaultUser()

            # Call the create_user method with the required arguments
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
    

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            vault_user = VaultUser()
            user = vault_user.authenticate(
                form.cleaned_data['username'], form.cleaned_data['password']
            )

            if user:
                request.session['username'] = user['username']
                return redirect('dashboard')
            else:
                if VaultUser().collection.find_one({'username': form.cleaned_data['username']}):
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

    # Fetch user document to get groups
    user = users_collection.find_one({'username': username})
    groups = user.get('groups', [])

    # Fetch all passwords for the user
    passwords_collection = get_passwords_collection()
    user_passwords = passwords_collection.find({'username': username})

    # Add passwords to each group (by ID)
    for group in groups:
        group_passwords = []
        for password_id in group['passwords']:
            password = passwords_collection.find_one({'_id': password_id})
            if password:
                group_passwords.append(password)

        # Add the passwords to each group
        group['passwords'] = group_passwords

    return render(request, 'dashboard.html', {'passwords': user_passwords, 'groups': groups, 'username': username})


    



def add_password(request):
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            group_id = request.POST.get('group_id', None)  # Optional group selection
            vault_user = VaultUser()
            result = vault_user.add_password(
                username=request.session.get('username'),
                service_name=form.cleaned_data['service_name'],
                password=form.cleaned_data['password'],
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


@csrf_exempt  # Use only if necessary; better to rely on CSRF tokens
def verify_account_password(request):
    if request.method == 'POST':
        try:
            import json
            body = json.loads(request.body.decode('utf-8'))
            account_password = body.get('account_password')

            # Fetch the stored user password
            username = request.session.get('username')
            if not username:
                return JsonResponse({'success': False, 'error': 'User not logged in.'}, status=400)

            from .models import VaultUser
            user = VaultUser().get_user_by_username(username)
            if not user:
                return JsonResponse({'success': False, 'error': 'User not found.'}, status=404)

            # Compare entered password with hashed password
            stored_password = user['password']  # Hashed password in database
            if bcrypt.checkpw(account_password.encode('utf-8'), stored_password):
                return JsonResponse({'success': True, 'password': user.get('actual_password')})
            else:
                return JsonResponse({'success': False, 'error': 'Incorrect password.'}, status=401)
        except Exception as e:
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
        return redirect('dashboard')  # Group not found, redirect to dashboard

    # Get password IDs from the group (these are UUID strings, not ObjectIds)
    group_password_ids = group.get('passwords', [])
    print("Group password IDs:", group_password_ids)

    # Fetch full password details from the passwords collection
    passwords_collection = get_passwords_collection()
    group_password_data = []

    # Use UUIDs as strings in the query
    for password_id in group_password_ids:
        password = passwords_collection.find_one({'_id': password_id})  # Use the UUID as a string in the query
        if password:
            group_password_data.append({
                'password_id': str(password['_id']),  # Store password_id as string for easy reference
                'service_name': password.get('service_name'),
                'password': password.get('password')
            })

    print("Matched passwords in group:", group_password_data)

    # Fetch all user's passwords to display for adding to the group
    user_passwords = [
        {**password, 'id': str(password['_id'])} for password in passwords_collection.find({'username': username})
    ]

    if request.method == 'POST':
        print("POST request received")
        remove_password_ids = request.POST.getlist('remove_passwords')
        add_password_ids = request.POST.getlist('add_passwords')

        print("Remove password IDs:", remove_password_ids)
        print("Add password IDs:", add_password_ids)

        # Ensure only the selected passwords are removed from the group
        updated_group_password_ids = [
            pwd_id for pwd_id in group_password_ids if pwd_id not in remove_password_ids
        ]

        print("Updated group passwords after removal:", updated_group_password_ids)

        # Add new selected passwords to the group
        for password_id in add_password_ids:
            if password_id not in updated_group_password_ids:
                updated_group_password_ids.append(password_id)

        print("Updated group passwords after adding:", updated_group_password_ids)

        # Update group in the database with the updated password IDs (not full details)
        users_collection.update_one(
            {'username': username, 'groups.group_id': group_id},
            {'$set': {'groups.$.passwords': updated_group_password_ids}}  # Only update password IDs
        )

        print("Changes saved successfully")
        return redirect('dashboard')

    return render(request, 'edit_group.html', {
        'group': group,
        'group_passwords': group_password_data,  # Render the full password details
        'user_passwords': user_passwords,
        'group_password_ids': group_password_ids,
        'group_id': group_id
    })









def user_logout(request):
    request.session.flush()
    return redirect('login')