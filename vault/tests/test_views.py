import json
import bcrypt
from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch


class ViewsTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123',
            'confirm_password': 'password123',
        }

    @patch('vault.views.VaultUser.create_user')
    def test_register_view_success(self, mock_create_user):
        mock_create_user.return_value = {'success': True}
        response = self.client.post(reverse('register'), self.user_data)
        self.assertEqual(response.status_code, 302)

    @patch('vault.views.VaultUser.authenticate')
    @patch('vault.views.VaultUser.send_2fa_email')
    def test_login_view_success_triggers_2fa(self, mock_send_2fa, mock_auth):
        mock_auth.return_value = {'username': 'testuser'}
        mock_send_2fa.return_value = {'success': True}
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn('awaiting_2fa', self.client.session)

    def test_welcome_view(self):
        response = self.client.get(reverse('welcome'))
        self.assertEqual(response.status_code, 200)

    def test_generate_password_view(self):
        response = self.client.post(reverse('generate_password'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('password', response.context)


    @patch('vault.views.VaultUser.edit_password')
    @patch('vault.views.VaultUser.get_user_by_username')
    @patch('vault.views.get_passwords_collection')  # Add this line
    def test_edit_password_success(self, mock_passwords_collection, mock_get_user, mock_edit_password):
     # Mock the database calls
     mock_find_one = mock_passwords_collection.return_value.find_one
     mock_find_one.return_value = {
         '_id': 'pwd123',
         'username': 'testuser',
         'service_name': 'old_service',
         'username_name': 'old_username'
      }
     
     mock_get_user.return_value = {
         'username': 'testuser',
         'password': bcrypt.hashpw("accountpass".encode(), bcrypt.gensalt())
     }
     mock_edit_password.return_value = {'success': True}
 
     # Simulate logged-in session
     session = self.client.session
     session['username'] = 'testuser'
     session.save()
 
     # POST to edit_password view
     response = self.client.post(reverse('edit_password', args=['pwd123']), {
         'service_name': 'gmail',
         'username_name': 'newuser',
         'password': 'newpass',
         'account_password': 'accountpass'
     })
 
     # If edit succeeds, view returns JSON
     self.assertEqual(response.status_code, 200)
     self.assertJSONEqual(response.content, {
         'success': True,
         'message': 'Password updated successfully.'
     })


    @patch('vault.views.VaultUser.delete_password')
    @patch('vault.views.VaultUser.get_user_by_username')
    def test_delete_password_success(self, mock_get_user, mock_delete_password):
     mock_get_user.return_value = {
         'username': 'testuser',
         'password': bcrypt.hashpw("accountpass".encode(), bcrypt.gensalt())
     }
     mock_delete_password.return_value = {'success': True}
 
     session = self.client.session
     session['username'] = 'testuser'
     session.save()
 
     response = self.client.post(reverse('delete_password'), data=json.dumps({
         '_id': 'pwd123',
         'account_password': 'accountpass'
     }), content_type='application/json')
 
     self.assertEqual(response.status_code, 200)
     self.assertJSONEqual(response.content, {'success': True, 'message': 'Password deleted successfully.'})

    @patch('vault.views.VaultUser.create_group')
    def test_create_group_view_success(self, mock_create_group):
     mock_create_group.return_value = {'success': True}
 
     session = self.client.session
     session['username'] = 'testuser'
     session.save()
 
     response = self.client.post(reverse('create_group'), {'name': 'Work'})
     self.assertEqual(response.status_code, 302)
         