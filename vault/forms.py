from django import forms

class RegistrationForm(forms.Form):
    username = forms.CharField(max_length=150)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")

        return cleaned_data



class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)


class GroupForm(forms.Form):
        name = forms.CharField(max_length=100, label='Group Name')


class PasswordForm(forms.Form):
    service_name = forms.CharField(max_length=100, label='Service Name')
    username_name = forms.CharField(max_length=100, label='Username')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')
    account_password = forms.CharField(
        widget=forms.PasswordInput,
        label='Your Account Password',
        help_text='Enter your account password to securely encrypt this entry'
    )
    
class TwoFactorForm(forms.Form):
    code = forms.CharField(
        label='Verification Code',
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={'placeholder': 'Enter 6-digit code'})
    )

    

    
