# coding: utf-8


# Base class for all errors, should not be raised
class Error(Exception): pass


#
# Generic errors
#

# Something went wrong with the network
class NetworkError(Error): pass


# Server responded with something we don't understand
class InvalidResponseError(Error): pass


# Server responded with XML we don't understand
class UnknownResponseSchemaError(Error): pass


#
# LastPass returned errors
#

# LastPass error: unknown username
class LastPassUnknownUsernameError(Error): pass


# LastPass error: invalid password
class LastPassInvalidPasswordError(Error): pass


# LastPass error: missing or incorrect Google Authenticator code
class LastPassIncorrectGoogleAuthenticatorCodeError(Error): pass


# LastPass error: missing or incorrect Yubikey password
class LastPassIncorrectYubikeyPasswordError(Error): pass


# LastPass error we don't know about
class LastPassUnknownError(Error): pass
