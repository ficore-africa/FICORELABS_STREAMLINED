from datetime import datetime
from utils import get_mongo_db, logger

def log_chat_interaction(session_id, user_id, question, response):
    """
    Log chat interactions to MongoDB.
    
    Args:
        session_id (str): Session ID
        user_id (str): User ID (optional)
        question (str): User's question
        response (str): Chatbot's response
    """
    try:
        db = get_mongo_db()
        chat_entry = {
            'session_id': session_id,
            'user_id': user_id if user_id else None,
            'question': question,
            'response': response,
            'timestamp': datetime.utcnow()
        }
        db.chat_history.insert_one(chat_entry)
        logger.info(f'Chat interaction logged for session {session_id}', extra={'session_id': session_id})
    except Exception as e:
        logger.error(f'Error logging chat interaction: {str(e)}', exc_info=True)