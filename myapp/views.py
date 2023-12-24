from cryptography.fernet import Fernet
from django.shortcuts import render
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.core.signing import Signer
from django.conf import settings
from .utils import private_key,public_key,deserialize_private_key,serialize_private_key


def encrypt_message(original_message, public_key):
    ciphertext = public_key.encrypt(
        original_message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Base64url encode the ciphertext
    base64url_encoded = base64.urlsafe_b64encode(ciphertext).decode()

    return base64url_encoded

def decrypt_message(encrypted_message, private_key):
    ciphertext = base64.urlsafe_b64decode(encrypted_message.encode())
    # Decrypt the ciphertext
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message.decode()

serialized_private_key = serialize_private_key(private_key)
retrieved_private_key = deserialize_private_key(serialized_private_key)

def process_form1(request):
    if request.method == 'POST':
        entered_text = request.POST.get('user_input', '')
        encrypted_message = encrypt_message(entered_text, public_key)
        generated_link = f'/show_encrypted_message/?message={encrypted_message}'
        
        return render(request, 'myapp/confirmation.html', {'entered_text': entered_text, 'generated_link': generated_link})

    else:
        return render(request, 'myapp/error.html')


def show_text(request):
    encoded_message = request.GET.get('message', '')
    try:
        decrypted_message = decrypt_message(encoded_message, retrieved_private_key)
        return render(request, 'myapp/show_text.html', {'entered_text': decrypted_message})
    except Exception as e:
        return render(request, 'myapp/error.html', {'error_message': f"Unexpected error: {str(e)}"})

def task_list(request):
    return render(request, 'myapp/task_list.html', {'tasks': ""})



# def generate_key():
#     return Fernet.generate_key()
# secret_key = generate_key()

def encrypt_message_fernet(message):
    hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend(),
        )
    key = base64.urlsafe_b64encode(hkdf.derive(bytes(settings.SECRET_KEY, "utf-8"))) #settings.SECRET_KEY we can stored in env
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(bytes(message, "utf-8")).decode()
    return encrypted_message

def decrypt_message_fernet(encrypted_message):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend(),
        )
    key = base64.urlsafe_b64encode(hkdf.derive(bytes(settings.SECRET_KEY, "utf-8")))
    cipher_suite = Fernet(key)
    decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
    return decrypted_message



def process_form2(request):
    if request.method == 'POST':
        entered_text = request.POST.get('user_input', '')
        
        encrypted_message=encrypt_message_fernet(entered_text)
        generated_link = f'/show_encrypted_message_fernet/?message={encrypted_message}'
        return render(request, 'myapp/confirmation.html', {'entered_text': entered_text, 'generated_link': generated_link})
    else:
        return render(request, 'myapp/error.html')
    
def show_text_fernet(request):
    encoded_message = request.GET.get('message', '')
    print("encoded message")
    try:
        decrypted_message = decrypt_message_fernet(encoded_message)
        print("decrypted_message",decrypted_message)
        return render(request, 'myapp/show_text.html', {'entered_text': decrypted_message})
    except Exception as e:
        return render(request, 'myapp/error.html', {'error_message': f"Unexpected error: {str(e)}"})

#signer


def sign_data_signer(message):
    signer = Signer(key=settings.SIGNER_SECRET_KEY)
    
    signed_data = signer.sign_object({"message":message})
    
    return signed_data    

def verify_data_signer(signed_data):
    signer = Signer(key=settings.SIGNER_SECRET_KEY)
    verified_data = signer.unsign_object(signed_data)

    return verified_data

def process_form3(request):
    if request.method == 'POST':
        entered_text = request.POST.get('user_input', '')
        signed_message=sign_data_signer(entered_text)
        generated_link = f'/show_encrypted_message_signer/?message={signed_message}'
        return render(request, 'myapp/confirmation.html', {'entered_text': entered_text, 'generated_link': generated_link})
    else:
        return render(request, 'myapp/error.html')

def show_text_signer(request):
    signed_message = request.GET.get('message', '')
    print("signed_message",signed_message)
    try:
        unsigned_message = verify_data_signer(signed_message)
        print("unsigned_message",unsigned_message)
        
        return render(request, 'myapp/show_text.html', {'entered_text': unsigned_message})
    except Exception as e:
        return render(request, 'myapp/error.html', {'error_message': f"Unexpected error: {str(e)}"})