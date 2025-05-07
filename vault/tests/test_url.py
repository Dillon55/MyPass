from django.urls import reverse
from django.test import SimpleTestCase

class UrlsTestCase(SimpleTestCase):
    
    def test_welcome_url(self):
        url = reverse('welcome')
        self.assertEqual(url, '/')
    
    def test_register_url(self):
        url = reverse('register')
        self.assertEqual(url, '/register/')
    
    def test_login_url(self):
        url = reverse('login')
        self.assertEqual(url, '/login/')
    
    def test_dashboard_url(self):
        url = reverse('dashboard')
        self.assertEqual(url, '/dashboard/')
    
    def test_add_password_url(self):
        url = reverse('add_password')
        self.assertEqual(url, '/add-password/')
    
    def test_create_group_url(self):
        url = reverse('create_group')
        self.assertEqual(url, '/create-group/')
    
    def test_logout_url(self):
        url = reverse('logout')
        self.assertEqual(url, '/logout/')
    
    def test_edit_group_url(self):
        url = reverse('edit_group', args=['group_id'])
        self.assertEqual(url, '/edit-group/group_id/')
    
    def test_verify_account_password_url(self):
        url = reverse('verify_account_password')
        self.assertEqual(url, '/verify_account_password/')
    
   
    def test_edit_password_url(self):
        url = reverse('edit_password', args=['password_id'])
        self.assertEqual(url, '/edit-password/password_id/')
    
    def test_decrypt_password_url(self):
        url = reverse('decrypt_password')
        self.assertEqual(url, '/decrypt_password/')
    
    def test_delete_password_url(self):
        url = reverse('delete_password')
        self.assertEqual(url, '/delete-password/')
    
    def test_delete_group_url(self):
        url = reverse('delete_group')
        self.assertEqual(url, '/delete_group/')
    
    def test_verify_2fa_url(self):
        url = reverse('verify_2fa')
        self.assertEqual(url, '/verify-2fa/')
    
    def test_resend_2fa_code_url(self):
        url = reverse('resend_2fa_code')
        self.assertEqual(url, '/resend-2fa-code/')
    
    def test_generate_password_url(self):
        url = reverse('generate_password')
        self.assertEqual(url, '/generate-password/')
    
    def test_cancel_2fa_url(self):
        url = reverse('cancel_2fa')
        self.assertEqual(url, '/cancel-2fa/')
