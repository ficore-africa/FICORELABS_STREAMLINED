from flask import Blueprint, request, jsonify, session
from flask_login import current_user
from .ai_helpers import process_dialogflow_request
from .chat_models import log_chat_interaction
from utils import get_user_language, logger
import json

ai_bp = Blueprint('ai', __name__, url_prefix='/ai')

@ai_bp.route('/webhook/dialogflow', methods=['POST'])
def dialogflow_webhook():
    """
    Handle Dialogflow webhook POST requests.
    
    Returns:
        JSON response for Dialogflow
    """
    try:
        request_data = request.get_data(as_text=True)
        lang = get_user_language()
        response = process_dialogflow_request(request_data, lang)
        
        # Log the interaction
        session_id = session.get('sid', 'no-session-id')
        user_id = current_user.id if current_user.is_authenticated else None
        question = json.loads(request_data)['queryResult']['queryText']
        log_chat_interaction(session_id, user_id, question, json.loads(response)['fulfillmentText'])
        
        return response
    except Exception as e:
        logger.error(f'Error in Dialogflow webhook: {str(e)}', exc_info=True)
        return jsonify({'fulfillmentText': 'An error occurred. Please try again later.'}), 500
