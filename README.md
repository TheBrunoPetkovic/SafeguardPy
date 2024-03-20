# SafeguardPy

SafeguardPy is a secure password manager that encrypts and stores your sensitive data on disk. It utilizes encryption algorithms such as Salsa20 and scrypt to ensure the confidentiality and integrity of your data.

## Features

- **Encryption**: SafeguardPy encrypts your address and password as pair before storing it on disk, ensuring that only authorized users with the master password can access the information.
- **Data Integrity**: The password manager verifies the integrity of the stored data to prevent tampering or unauthorized modifications.
- **Command-line Interface (CLI)**: SafeguardPy provides a simple command-line interface for initializing the password manager, storing new passwords, and retrieving existing passwords.

## Installation

1. Clone the repository:

    ```
    git clone https://github.com/TheBrunoPetkovic/SafeguardPy.git
    ```

2. Install the required dependencies:

    ```
    pip install pycryptodome
    ```

## Usage

To use SafeguardPy, follow these steps:

1. **Initialize Password Manager**:

    ```
    python safeguard.py init <choose_your_master_password>
    ```

    This command initializes the password manager with a master password. Make sure to remember this password, as it will be required to access your stored passwords.

2. **Store a New Password**:

    ```
    python safeguard.py put <master_password> <website_address> <password>
    ```

    Replace `<website_address>` with the name or URL of the website/application, and `<password>` with the corresponding password.

3. **Retrieve a Password**:

    ```
    python safeguard.py get <master_password> <website_address>
    ```

    Replace `<website_address>` with the name or URL of the website/application for which you want to retrieve the password.

## Security Considerations

- **Master Password**: Choose a strong and unique master password to protect your data. Avoid using common words or phrases.
- **Secure Storage**: SafeguardPy encrypts your data before storing it on disk. However, ensure that the system where the password manager is installed is secure to prevent unauthorized access to the encrypted data. SafeguardPy will keep your data secure even if tempered with, however if attacker gets access to data it will be lost.


## Acknowledgements

SafeguardPy utilizes the following cryptographic libraries:

- [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/): A collection of cryptographic algorithms and protocols implemented for use in Python.
