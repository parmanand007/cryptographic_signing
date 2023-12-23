from django.shortcuts import render
from django.urls import reverse
from urllib.parse import quote,unquote
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(serialized_key):
    return serialization.load_pem_private_key(
        serialized_key,
        password=None,
        backend=default_backend()
    )

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

private_key, public_key = generate_key_pair()
serialized_private_key = serialize_private_key(private_key)
# retrieved_private_key = deserialize_private_key(serialized_private_key)

def process_form1(request):
    if request.method == 'POST':
        entered_text = request.POST.get('user_input', '')
        encrypted_message = encrypt_message(entered_text, public_key)
        # encoded_message = quote(encrypted_message)
        print("encoded message",encrypted_message,len(encrypted_message))
        generated_link = f'/myapp/show_encrypted_message/?message={encrypted_message}'
        
        return render(request, 'myapp/confirmation.html', {'entered_text': entered_text, 'generated_link': generated_link})

    else:
        return render(request, 'myapp/error.html')


def show_text(request):
    encoded_message = request.GET.get('message', '')
    # encrypted_message = unquote(encoded_message)
    print("show text _ encrypted message",encoded_message,len(encoded_message))
    retrieved_private_key = deserialize_private_key(serialized_private_key)
    try:
        decrypted_message = decrypt_message(encoded_message, retrieved_private_key)
        return render(request, 'myapp/show_text.html', {'entered_text': decrypted_message})
    except Exception as e:
        return render(request, 'myapp/error.html', {'error_message': f"Unexpected error: {str(e)}"})

def task_list(request):
    return render(request, 'myapp/task_list.html', {'tasks': ""})

def process_form2(request):
    if request.method == 'POST':
        entered_text = request.POST.get('user_input', '')
        return render(request, 'myapp/confirmation.html', {'entered_text': entered_text})
    else:
        return render(request, 'myapp/error.html')

def process_form3(request):
    if request.method == 'POST':
        entered_text = request.POST.get('user_input', '')
        return render(request, 'myapp/confirmation.html', {'entered_text': entered_text})
    else:
        return render(request, 'myapp/error.html')
