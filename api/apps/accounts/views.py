from django.contrib.auth import authenticate, get_user_model
from rest_framework import generics, permissions, status, views
from rest_framework.response import Response
from django.forms.models import model_to_dict

from api.apps.accounts.models import Invitation, User
from ...exceptions import (
    AuthenticationFailed,
    NotFound,
    PermissionDenied
)
from ...utils import validate_required_fields
from .serializers import AcceptInviteSerializer, InvitationSerializer, UserSerializer
from .utils import (
    check_verification_token,
    create_user,
    custom_response_format,
    get_logged_in_user_response,
    update_or_create_auth_token,
    update_or_create_verification_token,
)



class LogInView(views.APIView):
    """
    View to log in a user and obtain an auth token.

    * No authentication.
    * Requires email and password.
    * Returns user object and token.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        password = request.data.get('password')
        validate_required_fields({'email': email, 'password': password})

        user = authenticate(username=email, password=password)
        if user is None:
            raise AuthenticationFailed
        else:
            return get_logged_in_user_response(user, status.HTTP_200_OK)


class CreateUserView(generics.CreateAPIView):
    """
    View to create a new user and send verification email.

    * No authentication.
    * Requires email, password, first_name, last_name.
    * Returns user object and token.
    """
    User = get_user_model()
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        user = create_user(request.data)

        return get_logged_in_user_response(user, status=status.HTTP_201_CREATED)


class RetrieveUserView(views.APIView):
    """
    View to retrieve a user's information with an auth token.

    * Authentication required.
    * Returns user object and token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return get_logged_in_user_response(
            request.user,
            status=status.HTTP_200_OK,
        )


class VerifyUserView(views.APIView):
    """
    View to verify a user account.

    * Authentication required.
    * Requires verification_token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        submitted_token = request.data.get('verification_token', '').strip()
        validate_required_fields({'verification_token': submitted_token})

        user = request.user
        verified_token = check_verification_token(submitted_token, user)

        user.is_verified = True
        user.save()
        verified_token.is_active = False
        verified_token.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class ResendVerificationEmailView(views.APIView):
    """
    View to request an account verification email to be resent.

    * Authentication required.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        verification_token = update_or_create_verification_token(request.user)
        print(verification_token)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ForgotPasswordView(views.APIView):
    """
    View to request a reset password email to be sent.

    * Requires email.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        validate_required_fields({'email': email})
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            print('User not found.')
        else:
            verification_token = update_or_create_verification_token(user)
            print(verification_token)

        return Response(status=status.HTTP_204_NO_CONTENT)


class ResetPasswordView(views.APIView):
    """
    View to reset a password using a token from email.

    * Requires email, password, verification_token.
    * Returns user object and token.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        password = request.data.get('password')
        submitted_token = request.data.get('verification_token', '').strip()
        validate_required_fields({
            'email': email,
            'password': password,
            'verification_token': submitted_token,
        })

        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            raise NotFound
        else:
            verified_token = check_verification_token(submitted_token, user)
            user.set_password(password)
            user.save()

            verified_token.is_active = False
            verified_token.save()
            update_or_create_auth_token(user)

            return get_logged_in_user_response(user, status.HTTP_200_OK)


class ChangePasswordView(views.APIView):
    """
    View to change a user's password.

    * Authentication required.
    * Requires current_password and new_password.
    * Returns token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        validate_required_fields({
            'current_password': current_password,
            'new_password': new_password,
        })

        user = authenticate(
            username=request.user.email,
            password=current_password,
        )
        if user is None:
            raise AuthenticationFailed
        elif user != request.user:
            raise PermissionDenied
        else:
            user.set_password(new_password)
            user.save()

            update_or_create_auth_token(user)

            return get_logged_in_user_response(
                user,
                status=status.HTTP_200_OK,
            )


class ChangeEmailView(views.APIView):
    """
    View to change a user's email.

    * Authentication required.
    * Requires email.
    * Returns user object and token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        validate_required_fields({'email': email})

        serializer = UserSerializer(
            request.user,
            data={'email': email},
            partial=True
        )
        serializer.is_valid(raise_exception=True)

        request.user.email = email
        request.user.username = email
        request.user.is_verified = False
        request.user.save()
        update_or_create_auth_token(request.user)

        verification_token = update_or_create_verification_token(request.user)
        print(verification_token)

        return get_logged_in_user_response(
            request.user,
            status=status.HTTP_200_OK,
        )


class UpdateUserView(views.APIView):
    """
    View to update a user's profile.

    * Authentication required.
    * Returns user object.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return get_logged_in_user_response(
            request.user,
            status=status.HTTP_200_OK,
        )


class CreateInviteView(views.APIView):
    """
    View creates new invite for a new user by existing user

    * Authentication required
    * Returns invitation id
    """
    permission_classes = [permissions.IsAuthenticated]


    def post(self, request, **kwargs):
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')

        serializer = InvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if Invitation.objects.filter(email=email).exists():
            return custom_response_format(status=status.HTTP_404_NOT_FOUND, 
                message="Email is already invited", 
                error="invite already exists"
            )
        invitation = Invitation.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            invited_by=request.user
        )
        
        return custom_response_format(status=status.HTTP_201_CREATED, 
            message="Invitation created successfully", 
            data={"id": invitation.id}
        )


class AcceptInviteView(views.APIView):
    """
    View accepts valid invites that exist
    * No Authentication
    * Require invite id
    * Returns user
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, **kwargs):
        print("kwargs.get) ->>", kwargs.get("id"))

        serizlier = AcceptInviteSerializer(data=request.data)
        serizlier.is_valid(raise_exception=True)

        try:
            invite = Invitation.objects.get(id=kwargs.get("id"))

            if not invite.is_active:
                return custom_response_format(status=status.HTTP_404_NOT_FOUND, 
                    message="Invite already accepted", 
                    error="invite already accepted"
                )

            user_obj ={
                "first_name" : invite.first_name,
                "last_name" : invite.last_name,
                "email"  :  invite.email,
                "password": serizlier.data.get("password")
            }

            user = create_user(user_obj)

            invite.is_active = False
            invite.save()

            return get_logged_in_user_response(user, status=status.HTTP_201_CREATED)

        except Invitation.DoesNotExist:
            return custom_response_format(status=status.HTTP_404_NOT_FOUND, 
                message="Invite not accepted", 
                error="invite id not found"
            )


class InviteDetailView(views.APIView):
    """
    View retrieves user's invitation

    * Authentication required
    * Returns Inviatation object
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, **kwargs):
        try:
            invite = Invitation.objects.get(pk=kwargs.get("id"))
            return custom_response_format(status=status.HTTP_200_OK, 
                message="Invite retrieved successfully", 
                data=model_to_dict(invite)
            )
        except Invitation.DoesNotExist:
            return custom_response_format(status=status.HTTP_404_NOT_FOUND, 
                message="Invite not found", 
                error="Invite not found"
            )



