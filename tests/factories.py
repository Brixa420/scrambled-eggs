"""
Test factories for creating test data.
"""

import uuid
from datetime import datetime, timedelta

import factory
from factory import Faker
from factory.alchemy import SQLAlchemyModelFactory

from app import db
from app.models.message import Message, MessageEdit, MessageMention, MessageReaction, MessageStatus
from app.models.user import User


class UserFactory(SQLAlchemyModelFactory):
    class Meta:
        model = User
        sqlalchemy_session = db.session
        sqlalchemy_session_persistence = "commit"

    id = factory.LazyFunction(uuid.uuid4)
    username = Faker("user_name")
    email = Faker("email")
    password_hash = Faker("sha256")
    created_at = Faker("date_time_this_year")
    is_active = True
    is_admin = False


class MessageFactory(SQLAlchemyModelFactory):
    class Meta:
        model = Message
        sqlalchemy_session = db.session
        sqlalchemy_session_persistence = "commit"

    id = factory.LazyFunction(uuid.uuid4)
    content = Faker("sentence")
    sender = factory.SubFactory(UserFactory)
    recipient = factory.SubFactory(UserFactory)
    status = MessageStatus.SENT
    created_at = Faker("date_time_this_month")
    updated_at = factory.LazyFunction(datetime.utcnow)
    deleted = False
    encrypted = False
    expires_at = None


class MessageEditFactory(SQLAlchemyModelFactory):
    class Meta:
        model = MessageEdit
        sqlalchemy_session = db.session
        sqlalchemy_session_persistence = "commit"

    id = factory.LazyFunction(uuid.uuid4)
    message = factory.SubFactory(MessageFactory)
    previous_content = Faker("sentence")
    edited_by = factory.SubFactory(UserFactory)
    reason = Faker("sentence")
    edited_at = Faker("date_time_this_month")


class MessageReactionFactory(SQLAlchemyModelFactory):
    class Meta:
        model = MessageReaction
        sqlalchemy_session = db.session
        sqlalchemy_session_persistence = "commit"

    id = factory.LazyFunction(uuid.uuid4)
    message = factory.SubFactory(MessageFactory)
    user = factory.SubFactory(UserFactory)
    reaction = Faker("emoji")
    created_at = Faker("date_time_this_month")


class MessageMentionFactory(SQLAlchemyModelFactory):
    class Meta:
        model = MessageMention
        sqlalchemy_session = db.session
        sqlalchemy_session_persistence = "commit"

    id = factory.LazyFunction(uuid.uuid4)
    message = factory.SubFactory(MessageFactory)
    user = factory.SubFactory(UserFactory)
    mentioned_by = factory.SubFactory(UserFactory)
    created_at = Faker("date_time_this_month")
