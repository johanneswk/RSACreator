#!/usr/bin/env python
# This program creates a private/public key-pair for a student at the HvA

__author__ = '{Johannes Kistemaker}'
__email__ = '{johannes.kistemaker@hva.nl}'

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os.path


def pem_formatter(key, version):
    if version == "private":
        # Format private key in PEM format
        pem_key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption())
        return pem_key
    if version == "public":
        # Format public key in PEM format
        pem_key = key.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem_key


def generate_private():
    private = rsa.generate_private_key(backend=default_backend(), public_exponent=65537,
                                       key_size=2048)
    version = "private"
    pem_private = pem_formatter(private, version)
    return private, pem_private


def generate_public():
    public = private_key.public_key()
    version = "public"
    pem_public = pem_formatter(public, version)
    return public, pem_public


def write_keys():
    # Check if file(s) already exist
    if not (os.path.isfile(str(studentnumber) + (".key" or ".pem"))):
        # Write private and public keys to disk
        with open(str(studentnumber) + ".key", 'wb') as f:
            f.write(pem_private)
        with open(str(studentnumber) + ".pem", 'wb') as g:
            g.write(pem_public)
    else:
        raise FileExistsError


if __name__ == '__main__':
    try:
        # Welcome and input
        print("Welcome to this private/public key-pair generator\n")
        studentnumber = int(input("Enter your school studentnumber: "))

        # Generate private key
        private_key, pem_private = generate_private()

        # Generate public key with use of private key
        public_key, pem_public = generate_public()

        # Store keys on disk
        write_keys()
        print("Keys have been created and saved successfully!")

    except ValueError:
        # Catching user-input that cannot be parsed as an int
        print("Entered studentnumber is not correct!")
        exit(2)

    except FileExistsError:
        # Catching if file already exists for user
        print("Keys have already been created for this user!")
        exit(3)
    except:
        # Throw way too generic error end exit
        print("Error in creating keys")
        exit(1)
