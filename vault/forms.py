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
    service_name = forms.CharField(label="Service Name", max_length=100)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
    

    

    
