import imp
import factory

from ..models import Invitation, User


class UserFactory(factory.django.DjangoModelFactory):

    class Meta:
        model = User

    username = factory.Sequence(lambda n: f"account-{n}@mailer.com")


class InvitationFactory(factory.django.DjangoModelFactory):

    class Meta:
        model = Invitation

    invited_by = factory.SubFactory(UserFactory)