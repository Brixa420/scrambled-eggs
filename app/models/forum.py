from datetime import datetime
from app import db
from sqlalchemy.sql import func

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    karma = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')
    votes = db.relationship('Vote', backref='user', lazy='dynamic')
    awards_given = db.relationship('Award', foreign_keys='Award.giver_id', backref='giver', lazy='dynamic')
    awards_received = db.relationship('Award', foreign_keys='Award.receiver_id', backref='receiver', lazy='dynamic')

class Post(db.Model):
    __tablename__ = 'posts'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    score = db.Column(db.Integer, default=0)
    comment_count = db.Column(db.Integer, default=0)
    is_deleted = db.Column(db.Boolean, default=False)
    
    # Foreign Keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subreddit_id = db.Column(db.Integer, db.ForeignKey('subreddits.id'), nullable=False)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy='dynamic', 
                             cascade='all, delete-orphan')
    votes = db.relationship('Vote', backref='post', lazy='dynamic', 
                           cascade='all, delete-orphan')
    awards = db.relationship('Award', backref='post', lazy='dynamic')
    
    @property
    def upvotes(self):
        return self.votes.filter_by(vote_type='upvote').count()
    
    @property
    def downvotes(self):
        return self.votes.filter_by(vote_type='downvote').count()

class Comment(db.Model):
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    score = db.Column(db.Integer, default=0)
    is_deleted = db.Column(db.Boolean, default=False)
    
    # Foreign Keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    
    # Relationships
    votes = db.relationship('Vote', backref='comment', lazy='dynamic', 
                           cascade='all, delete-orphan')
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]),
                             lazy='dynamic', cascade='all, delete-orphan')
    awards = db.relationship('Award', backref='comment', lazy='dynamic')
    
    @property
    def upvotes(self):
        return self.votes.filter_by(vote_type='upvote').count()
    
    @property
    def downvotes(self):
        return self.votes.filter_by(vote_type='downvote').count()

class Vote(db.Model):
    __tablename__ = 'votes'
    
    id = db.Column(db.Integer, primary_key=True)
    vote_type = db.Column(db.Enum('upvote', 'downvote', name='vote_types'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign Keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    
    # Ensure a vote is either for a post or a comment, not both
    __table_args__ = (
        db.CheckConstraint(
            '(post_id IS NOT NULL AND comment_id IS NULL) OR (post_id IS NULL AND comment_id IS NOT NULL)',
            name='vote_target_check'
        ),
    )

class AwardType(db.Model):
    __tablename__ = 'award_types'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    description = db.Column(db.Text)
    cost = db.Column(db.Integer, nullable=False)  # in karma points
    icon = db.Column(db.String(255))  # URL to award icon
    
    # Relationships
    awards = db.relationship('Award', backref='award_type', lazy='dynamic')

class Award(db.Model):
    __tablename__ = 'awards'
    
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign Keys
    award_type_id = db.Column(db.Integer, db.ForeignKey('award_types.id'), nullable=False)
    giver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    
    # Ensure an award is either for a post or a comment, not both
    __table_args__ = (
        db.CheckConstraint(
            '(post_id IS NOT NULL AND comment_id IS NULL) OR (post_id IS NULL AND comment_id IS NOT NULL)',
            name='award_target_check'
        ),
    )

class Subreddit(db.Model):
    __tablename__ = 'subreddits'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    subscriber_count = db.Column(db.Integer, default=0)
    is_private = db.Column(db.Boolean, default=False)
    
    # Relationships
    posts = db.relationship('Post', backref='subreddit', lazy='dynamic')
    moderators = db.relationship('User', secondary='subreddit_moderators', 
                               backref=db.backref('moderated_subreddits', lazy='dynamic'))
    subscribers = db.relationship('User', secondary='subreddit_subscribers',
                                backref=db.backref('subscriptions', lazy='dynamic'))

# Association tables for many-to-many relationships
subreddit_moderators = db.Table('subreddit_moderators',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('subreddit_id', db.Integer, db.ForeignKey('subreddits.id'), primary_key=True),
    db.Column('assigned_at', db.DateTime, default=datetime.utcnow)
)

subreddit_subscribers = db.Table('subreddit_subscribers',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('subreddit_id', db.Integer, db.ForeignKey('subreddits.id'), primary_key=True),
    db.Column('subscribed_at', db.DateTime, default=datetime.utcnow)
)
