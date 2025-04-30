from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, content, username):
        self.content = content
        self.username = username
    
    def to_dict(self):
        """Convert message to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'message': self.content,
            'username': self.username,
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    @classmethod
    def get_recent_messages(cls, limit=100):
        """Get the most recent messages from the database in chronological order (oldest first)"""
        # Query messages in descending order (newest first), limit, then reverse for display
        messages = cls.query.order_by(cls.created_at.desc()).limit(limit).all()
        # Reverse the list to get chronological order (oldest first)
        return list(reversed(messages)) 