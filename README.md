Welcome to the My App Documentation

1. **RSA Encryption:**
    - `generate_key_pair()`: This function creates a pair of cryptographic keys – a private key for secure data decryption and a public key for encrypting sensitive information.

    - `serialize_private_key(private_key)`: Converts the private key into a format suitable for storage and later retrieval.

    - `encrypt_message(original_message, public_key)`: Encrypts a given message using the provided public key and return Base64url encoded ciphertext.

    - `deserialize_private_key(serialized_key)`: Deserializes a private key from its serialized PEM format
    
    - `decrypt_message(encrypted_message, private_key)`: Utilizes the private key to decrypt the encrypted message, revealing the original content.


2. **Fernet Encryption:**
    - `generate_key()`: This function generates a secret key for symmetric encryption using Fernet.

    - `encrypt_message_fernet(message)`: Encrypts the given message using Fernet encryption, ensuring confidentiality.

    - `decrypt_message_fernet(encrypted_message)`: Decrypts a Fernet-encrypted message, providing access to the original content.

3. **Django Signer:**
    - `sign_data_signer(message)`: Digitally signs the provided message, adding a layer of authentication.

    - `verify_data_signer(signed_data)`: Verifies the authenticity of a signed message, ensuring it hasn't been tampered with.

4. **Task List:**
    - `task_list(request)`: Displays your current tasks, providing an organized view of ongoing activities.

5. **Error Handling:**
    - If at any point an unexpected error occurs, you will be redirected to an error page (`error.html`), displaying a message describing the issue.

6. **Best Practices:**
    - Keep your cryptographic keys (`private_key`, `public_key`, `signer_secret_key`) secure and never expose them in your code or share them publicly.

    - It's recommended to store sensitive information like the secret key  in environment variables rather than hardcoding them in your code.

7. **Task List:**
    - The `task_list(request)` view provides a simple task list interface. You can customize and enhance this functionality based on your specific task management needs.

8. **Security Considerations:**
    - Ensure that your Django application is configured securely. Follow Django best practices for security, including using HTTPS, securing your database, and keeping your Django version up to date.

9. **Customization:**
    - Feel free to customize the provided views (`process_form1`, `process_form2`, `process_form3`, etc.) based on your application's requirements. Add additional features, validation, or UI improvements to enhance the user experience.

10. **Further Assistance:**
    - If you have any questions, encounter issues, or need further assistance, don't hesitate to reach out to our support team. I'am here to help you make the most out of your My App experience.

11. **Collaboration and Feedback:**
    - I value your feedback and collaboration. If you have suggestions for improvements or new features, please let us know. I appreciate your contribution to making My App better.

12. **Conclusion:**
    - Thank you for choosing My App! We hope this application serves your needs for secure data handling and encryption. If you have any additional queries or feedback, feel free to contact us.

Remember, your security and satisfaction are our top priorities. We look forward to continuing to support you on your journey with My App!


How to Use:
- **SETUP ENV:**
    -Set SIGNER_SECRET_KEY,SECRET_KEY in .env file
- **RSA Encryption:**
    - Submit your input using the form in `process_form1(request)`.
    - Receive a secure link that only you can access.
    - Click on the link to unveil your encrypted information using `show_text(request)`.

- **Fernet Encryption:**
    - Enter your text through the form in `process_form2(request)`.
    - Obtain a secure link for accessing the encrypted content.
    - Decode and view the original text using `show_text_fernet(request)`.

- **Django Signer:**
    - Input your text using the provided form in `process_form3(request)`.
    - Receive a digitally signed link for secure sharing.
    - Verify the authenticity of the received message using `show_text_signer(request)`.

Note: Each encryption method provides a unique way to secure and share your information. If you encounter any issues or have questions, feel free to contact me.

Thank you for choosing My App!
