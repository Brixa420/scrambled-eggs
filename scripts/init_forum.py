#!/usr/bin/env python3
"""
Initialize the forum database with sample data.
"""
import sys
import os
from datetime import datetime, timedelta
import random
from faker import Faker

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.forum import (
    User, Post, Comment, Vote, AwardType, Award, Subreddit,
    subreddit_moderators, subreddit_subscribers
)

def create_sample_data():
    """Create sample data for the forum."""
    app = create_app()
    with app.app_context():
        # Clear existing data
        db.drop_all()
        db.create_all()
        
        fake = Faker()
        
        # Create users
        print("Creating users...")
        users = []
        for _ in range(20):
            user = User(
                username=fake.unique.user_name(),
                email=fake.unique.email(),
                password_hash=fake.sha256(),
                created_at=fake.date_time_this_year(),
                karma=random.randint(0, 10000)
            )
            users.append(user)
            db.session.add(user)
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash='$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',  # 'password'
            is_admin=True,
            karma=10000
        )
        db.session.add(admin)
        users.append(admin)
        
        # Create subreddits
        print("Creating subreddits...")
        subreddits = []
        subreddit_names = [
            'programming', 'gaming', 'movies', 'music', 'books',
            'technology', 'science', 'history', 'art', 'food'
        ]
        
        for name in subreddit_names:
            subreddit = Subreddit(
                name=name,
                description=fake.sentence(),
                created_at=fake.date_time_this_year(),
                subscriber_count=random.randint(1000, 1000000)
            )
            subreddits.append(subreddit)
            db.session.add(subreddit)
        
        db.session.commit()
        
        # Add moderators to subreddits
        print("Adding moderators...")
        for subreddit in subreddits:
            # Each subreddit gets 1-3 moderators
            num_mods = random.randint(1, 3)
            mods = random.sample(users, num_mods)
            
            for mod in mods:
                if mod not in subreddit.moderators:
                    subreddit.moderators.append(mod)
        
        # Add subscribers to subreddits
        print("Adding subscribers...")
        for user in users:
            # Each user subscribes to 3-8 random subreddits
            num_subs = random.randint(3, 8)
            subs = random.sample(subreddits, num_subs)
            
            for sub in subs:
                if sub not in user.subscriptions:
                    user.subscriptions.append(sub)
        
        db.session.commit()
        
        # Create award types
        print("Creating award types...")
        award_types = [
            {"name": "Gold", "description": "Gives the author 100 Coins and a week of Lounge access", "cost": 500, "icon": "🥇"},
            {"name": "Platinum", "description": "Gives the author 700 Coins and a month of Lounge access", "cost": 2400, "icon": "💎"},
            {"name": "Silver", "description": "Shows the love", "cost": 100, "icon": "🥈"},
            {"name": "Helpful", "description": "Thanks for being helpful", "cost": 200, "icon": "🙏"},
            {"name": "Wholesome", "description": "For warm fuzzies", "cost": 200, "icon": "😊"},
            {"name": "I'm Deceased", "description": "I'm dead", "cost": 300, "icon": "💀"},
            {"name": "Take My Energy", "description": "All the power to you!", "cost": 200, "icon": "⚡"},
            {"name": "This", "description": "This.", "cost": 100, "icon": "⬆️"},
        ]
        
        for award_data in award_types:
            award = AwardType(**award_data)
            db.session.add(award)
        
        db.session.commit()
        
        # Create posts
        print("Creating posts...")
        posts = []
        for _ in range(100):
            author = random.choice(users)
            subreddit = random.choice(subreddits)
            
            post = Post(
                title=fake.sentence(),
                content='\n\n'.join(fake.paragraphs(nb=random.randint(1, 5))),
                created_at=fake.date_time_this_year(),
                score=random.randint(-100, 1000),
                comment_count=random.randint(0, 200),
                user_id=author.id,
                subreddit_id=subreddit.id
            )
            posts.append(post)
            db.session.add(post)
        
        db.session.commit()
        
        # Create comments
        print("Creating comments...")
        comments = []
        for post in posts:
            # Each post gets 5-20 comments
            num_comments = random.randint(5, 20)
            
            for _ in range(num_comments):
                author = random.choice(users)
                
                # 70% chance of being a top-level comment
                if not comments or random.random() > 0.7:
                    parent = None
                else:
                    # Otherwise, reply to a random existing comment
                    parent = random.choice(comments)
                
                comment = Comment(
                    content='\n\n'.join(fake.paragraphs(nb=random.randint(1, 3))),
                    created_at=fake.date_time_between_dates(
                        datetime_start=post.created_at,
                        datetime_end=datetime.utcnow()
                    ),
                    score=random.randint(-50, 500),
                    user_id=author.id,
                    post_id=post.id,
                    parent_id=parent.id if parent else None
                )
                comments.append(comment)
                db.session.add(comment)
        
        db.session.commit()
        
        # Create votes
        print("Creating votes...")
        for user in users:
            # Vote on random posts
            voted_posts = random.sample(posts, min(50, len(posts)))
            for post in voted_posts:
                vote = Vote(
                    vote_type=random.choices(
                        ['upvote', 'downvote'],
                        weights=[0.8, 0.2],  # 80% upvotes, 20% downvotes
                        k=1
                    )[0],
                    user_id=user.id,
                    post_id=post.id
                )
                db.session.add(vote)
            
            # Vote on random comments
            voted_comments = random.sample(comments, min(100, len(comments)))
            for comment in voted_comments:
                vote = Vote(
                    vote_type=random.choices(
                        ['upvote', 'downvote'],
                        weights=[0.8, 0.2],
                        k=1
                    )[0],
                    user_id=user.id,
                    comment_id=comment.id
                )
                db.session.add(vote)
        
        db.session.commit()
        
        # Create awards
        print("Creating awards...")
        all_awards = AwardType.query.all()
        
        for _ in range(50):  # Create 50 random awards
            award_type = random.choice(all_awards)
            giver = random.choice(users)
            
            # 70% chance to award a post, 30% a comment
            if random.random() < 0.7 and posts:
                target = random.choice(posts)
                award = Award(
                    award_type_id=award_type.id,
                    giver_id=giver.id,
                    receiver_id=target.user_id,
                    post_id=target.id
                )
            elif comments:  # Only if there are comments
                target = random.choice(comments)
                award = Award(
                    award_type_id=award_type.id,
                    giver_id=giver.id,
                    receiver_id=target.user_id,
                    comment_id=target.id
                )
            else:
                continue
            
            # Update user karma
            giver.karma -= award_type.cost
            
            db.session.add(award)
        
        db.session.commit()
        
        print("Sample data created successfully!")

if __name__ == '__main__':
    create_sample_data()
