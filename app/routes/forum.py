from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.forum import (
    User, Post, Comment, Vote, Award, AwardType, Subreddit,
    subreddit_moderators, subreddit_subscribers, db
)
from datetime import datetime
from sqlalchemy import or_

bp = Blueprint('forum', __name__, url_prefix='/api/forum')

def get_current_user():
    """Get the current user from JWT token"""
    user_id = get_jwt_identity()
    return User.query.get(user_id)

def calculate_karma(user_id):
    """Calculate a user's total karma from posts and comments"""
    post_karma = db.session.query(
        db.func.sum(Post.score)
    ).filter_by(user_id=user_id).scalar() or 0
    
    comment_karma = db.session.query(
        db.func.sum(Comment.score)
    ).filter_by(user_id=user_id).scalar() or 0
    
    return post_karma + comment_karma

# Posts endpoints
@bp.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    """Create a new post"""
    current_user = get_current_user()
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['title', 'content', 'subreddit_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if subreddit exists and is not private
    subreddit = Subreddit.query.get(data['subreddit_id'])
    if not subreddit:
        return jsonify({'error': 'Subreddit not found'}), 404
    
    if subreddit.is_private and subreddit.id not in [s.id for s in current_user.subscriptions]:
        return jsonify({'error': 'This is a private subreddit'}), 403
    
    # Create post
    post = Post(
        title=data['title'],
        content=data['content'],
        user_id=current_user.id,
        subreddit_id=subreddit.id
    )
    
    db.session.add(post)
    db.session.commit()
    
    return jsonify({
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'created_at': post.created_at.isoformat(),
        'author': current_user.username,
        'subreddit': subreddit.name,
        'score': post.score
    }), 201

@bp.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    """Get a single post with comments"""
    post = Post.query.get_or_404(post_id)
    
    # Get top-level comments with pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    sort = request.args.get('sort', 'top')  # top, new, controversial, etc.
    
    # Build base query
    comments_query = Comment.query.filter_by(
        post_id=post_id,
        parent_id=None
    )
    
    # Apply sorting
    if sort == 'new':
        comments_query = comments_query.order_by(Comment.created_at.desc())
    elif sort == 'controversial':
        # Sort by ratio of upvotes to downvotes (simplified)
        comments_query = comments_query.order_by(
            (Comment.votes.filter_by(vote_type='upvote').count() - 
             Comment.votes.filter_by(vote_type='downvote').count()).desc()
        )
    else:  # Default to top
        comments_query = comments_query.order_by(Comment.score.desc())
    
    # Paginate
    pagination = comments_query.paginate(page=page, per_page=per_page, error_out=False)
    comments = pagination.items
    
    # Build response
    post_data = {
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'created_at': post.created_at.isoformat(),
        'author': post.author.username,
        'subreddit': post.subreddit.name,
        'score': post.score,
        'comment_count': post.comment_count,
        'upvotes': post.upvotes,
        'downvotes': post.downvotes,
        'comments': [
            build_comment_tree(comment, max_depth=3)  # Limit recursion depth
            for comment in comments
        ],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total
        }
    }
    
    return jsonify(post_data)

def build_comment_tree(comment, current_depth=0, max_depth=3):
    """Recursively build a tree of comments and replies"""
    if current_depth >= max_depth:
        return {
            'id': comment.id,
            'content': comment.content,
            'author': comment.author.username,
            'score': comment.score,
            'created_at': comment.created_at.isoformat(),
            'upvotes': comment.upvotes,
            'downvotes': comment.downvotes,
            'replies': []
        }
    
    return {
        'id': comment.id,
        'content': comment.content,
        'author': comment.author.username,
        'score': comment.score,
        'created_at': comment.created_at.isoformat(),
        'upvotes': comment.upvotes,
        'downvotes': comment.downvotes,
        'replies': [
            build_comment_tree(reply, current_depth + 1, max_depth)
            for reply in comment.replies.all()
        ]
    }

# Comments endpoints
@bp.route('/posts/<int:post_id>/comments', methods=['POST'])
@jwt_required()
def create_comment(post_id):
    """Create a new comment on a post"""
    current_user = get_current_user()
    data = request.get_json()
    
    # Validate required fields
    if 'content' not in data:
        return jsonify({'error': 'Comment content is required'}), 400
    
    # Check if post exists
    post = Post.query.get_or_404(post_id)
    
    # Create comment
    comment = Comment(
        content=data['content'],
        user_id=current_user.id,
        post_id=post_id,
        parent_id=data.get('parent_id')
    )
    
    # Update post comment count
    post.comment_count = Comment.query.filter_by(post_id=post_id).count() + 1
    
    db.session.add(comment)
    db.session.commit()
    
    return jsonify({
        'id': comment.id,
        'content': comment.content,
        'created_at': comment.created_at.isoformat(),
        'author': current_user.username,
        'score': comment.score,
        'parent_id': comment.parent_id,
        'post_id': comment.post_id
    }), 201

# Voting endpoints
@bp.route('/vote', methods=['POST'])
@jwt_required()
def vote():
    """Vote on a post or comment"""
    current_user = get_current_user()
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['vote_type', 'target_type', 'target_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if data['vote_type'] not in ['upvote', 'downvote']:
        return jsonify({'error': 'Invalid vote type'}), 400
    
    if data['target_type'] not in ['post', 'comment']:
        return jsonify({'error': 'Invalid target type'}), 400
    
    # Check if target exists
    target_model = Post if data['target_type'] == 'post' else Comment
    target = target_model.query.get(data['target_id'])
    
    if not target:
        return jsonify({'error': f'{data["target_type"].capitalize()} not found'}), 404
    
    # Check if user already voted
    existing_vote = Vote.query.filter_by(
        user_id=current_user.id,
        **{f'{data["target_type"]}_id': data['target_id']}
    ).first()
    
    if existing_vote:
        if existing_vote.vote_type == data['vote_type']:
            # Remove vote if clicking the same button again
            db.session.delete(existing_vote)
            target.score -= 1 if data['vote_type'] == 'upvote' else -1
        else:
            # Change vote type
            if existing_vote.vote_type == 'upvote' and data['vote_type'] == 'downvote':
                target.score -= 2  # Remove upvote and add downvote
            elif existing_vote.vote_type == 'downvote' and data['vote_type'] == 'upvote':
                target.score += 2  # Remove downvote and add upvote
            existing_vote.vote_type = data['vote_type']
    else:
        # Create new vote
        vote = Vote(
            vote_type=data['vote_type'],
            user_id=current_user.id,
            **{f'{data["target_type"]}_id': data['target_id']}
        )
        target.score += 1 if data['vote_type'] == 'upvote' else -1
        db.session.add(vote)
    
    db.session.commit()
    
    # Update user karma
    if data['target_type'] == 'post':
        target.author.karma = calculate_karma(target.author.id)
    else:  # comment
        target.author.karma = calculate_karma(target.author.id)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'new_score': target.score,
        'user_karma': target.author.karma
    })

# Subreddit endpoints
@bp.route('/subreddits', methods=['GET'])
def get_subreddits():
    """Get a list of subreddits"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = Subreddit.query
    
    if search:
        query = query.filter(Subreddit.name.ilike(f'%{search}%'))
    
    pagination = query.order_by(Subreddit.subscriber_count.desc())\
                     .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'subreddits': [{
            'id': sub.id,
            'name': sub.name,
            'description': sub.description,
            'subscriber_count': sub.subscriber_count,
            'is_private': sub.is_private
        } for sub in pagination.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total
        }
    })

@bp.route('/subreddits/<int:subreddit_id>/subscribe', methods=['POST'])
@jwt_required()
def subscribe_subreddit(subreddit_id):
    """Subscribe to a subreddit"""
    current_user = get_current_user()
    subreddit = Subreddit.query.get_or_404(subreddit_id)
    
    if subreddit in current_user.subscriptions:
        return jsonify({'error': 'Already subscribed'}), 400
    
    current_user.subscriptions.append(subreddit)
    subreddit.subscriber_count += 1
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'subscriber_count': subreddit.subscriber_count
    })

# User endpoints
@bp.route('/users/<username>', methods=['GET'])
def get_user_profile(username):
    """Get user profile and activity"""
    user = User.query.filter_by(username=username).first_or_404()
    
    # Get user's top posts and comments
    top_posts = Post.query.filter_by(user_id=user.id)\
                         .order_by(Post.score.desc())\
                         .limit(5).all()
    
    top_comments = Comment.query.filter_by(user_id=user.id)\
                              .order_by(Comment.score.desc())\
                              .limit(5).all()
    
    return jsonify({
        'username': user.username,
        'created_at': user.created_at.isoformat(),
        'karma': user.karma,
        'top_posts': [{
            'id': post.id,
            'title': post.title,
            'score': post.score,
            'subreddit': post.subreddit.name,
            'created_at': post.created_at.isoformat()
        } for post in top_posts],
        'top_comments': [{
            'id': comment.id,
            'content': comment.content[:200] + ('...' if len(comment.content) > 200 else ''),
            'score': comment.score,
            'post_id': comment.post_id,
            'created_at': comment.created_at.isoformat()
        } for comment in top_comments]
    })

# Award endpoints
@bp.route('/awards', methods=['GET'])
def get_award_types():
    """Get available award types"""
    awards = AwardType.query.all()
    
    return jsonify([{
        'id': award.id,
        'name': award.name,
        'description': award.description,
        'cost': award.cost,
        'icon': award.icon
    } for award in awards])

@bp.route('/awards/give', methods=['POST'])
@jwt_required()
def give_award():
    """Give an award to a post or comment"""
    current_user = get_current_user()
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['award_type_id', 'target_type', 'target_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if data['target_type'] not in ['post', 'comment']:
        return jsonify({'error': 'Invalid target type'}), 400
    
    # Check if award type exists
    award_type = AwardType.query.get(data['award_type_id'])
    if not award_type:
        return jsonify({'error': 'Invalid award type'}), 404
    
    # Check if user has enough karma
    if current_user.karma < award_type.cost:
        return jsonify({'error': 'Not enough karma'}), 400
    
    # Check if target exists
    target_model = Post if data['target_type'] == 'post' else Comment
    target = target_model.query.get(data['target_id'])
    
    if not target:
        return jsonify({'error': f'{data["target_type"].capitalize()} not found'}), 404
    
    # Create award
    award = Award(
        award_type_id=award_type.id,
        giver_id=current_user.id,
        receiver_id=target.user_id,
        **{f'{data["target_type"]}_id': data['target_id']}
    )
    
    # Update karma
    current_user.karma -= award_type.cost
    target.author.karma += award_type.cost  # Receiver gets karma
    
    db.session.add(award)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'award_id': award.id,
        'awarded_to': target.author.username,
        'award_type': award_type.name,
        'remaining_karma': current_user.karma
    })
