import unittest
from unittest.mock import patch, MagicMock
from vault.models import VaultUser
import bcrypt


class VaultUserModelTest(unittest.TestCase):

    @patch('vault.models.get_users_collection')
    def setUp(self, mock_get_users):
        self.mock_users = MagicMock()
        mock_get_users.return_value = self.mock_users
        self.mock_users.find_one.side_effect = lambda query: None
        self.vault = VaultUser()

    def test_encrypt_decrypt_password(self):
        password = "mypassword123"
        master_password = "masterpass"
        encrypted = self.vault.encrypt_password(password, master_password)
        decrypted = self.vault.decrypt_password(encrypted, master_password)
        self.assertEqual(password, decrypted)

    def test_create_user_success(self):
        self.mock_users.find_one.side_effect = lambda q: None
        self.mock_users.insert_one.return_value = MagicMock()
        result = self.vault.create_user("newuser", "new@example.com", "pass123")
        self.assertTrue(result['success'])

    def test_create_user_existing_username(self):
        self.mock_users.find_one.side_effect = lambda q: {'username': 'newuser'} if 'username' in q else None
        result = self.vault.create_user("newuser", "new@example.com", "pass123")
        self.assertFalse(result['success'])

    def test_generate_2fa_code_and_verify(self):
        self.mock_users.update_one = MagicMock()
        code = self.vault.generate_2fa_code("user")
        self.assertEqual(len(code), 6)

    def test_authenticate_success(self):
        self.vault.collection = MagicMock()
        self.vault.collection.find_one.return_value = {
            'username': 'user',
            'password': bcrypt.hashpw("pass".encode(), bcrypt.gensalt())
        }
        user = self.vault.authenticate("user", "pass")
        self.assertIsNotNone(user)

    def test_get_user_passwords(self):
        with patch('vault.models.get_passwords_collection') as mock_get_passwords:
            mock_col = MagicMock()
            mock_col.find.return_value = [{'_id': '1', 'username': 'user', 'service_name': 'gmail'}]
            mock_get_passwords.return_value = mock_col
            result = VaultUser.get_user_passwords('user')
            self.assertEqual(len(result), 1)
            
            
    @patch('vault.models.get_passwords_collection')
    def test_add_password(self, mock_get_passwords):
     passwords_collection = MagicMock()
     mock_get_passwords.return_value = passwords_collection
     passwords_collection.insert_one.return_value = MagicMock()
     self.vault.collection.update_one = MagicMock()

     result = self.vault.add_password(
        username='testuser',
        service_name='gmail',
        username_name='user@gmail.com',
        password='mypassword',
        master_password='master123',
        group_id='group123'
     )
     self.assertTrue(result['success'])

    @patch('vault.models.get_passwords_collection')
    def test_delete_password_success(self, mock_get_passwords):
     passwords_collection = MagicMock()
     passwords_collection.find_one.return_value = {'_id': 'pwd123', 'username': 'testuser'}
     passwords_collection.delete_one.return_value = MagicMock()
     mock_get_passwords.return_value = passwords_collection

     result = self.vault.delete_password('testuser', 'pwd123')
     self.assertTrue(result['success'])

    def test_create_group_success(self):
     self.mock_users.update_one.return_value.modified_count = 1
     result = self.vault.create_group('testuser', 'Work')
     self.assertTrue(result['success'])

