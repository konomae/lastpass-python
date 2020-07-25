# coding: utf-8
class Authenticator(object):
    def __init__(self, accountID, digits, issuerName, lmiUserId, originalIssuerName, originalUserName, pushNotification, secret, timeStep, userName):
        self.accountID = accountID
        self.digits = digits
        self.issuerName = issuerName
        self.lmiUserId = lmiUserId
        self.originalIssuerName = originalIssuerName
        self.originalUserName = originalUserName
        self.pushNotification = pushNotification
        self.secret = secret
        self.timeStep = timeStep
        self.userName = userName
