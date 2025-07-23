from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
from bson import ObjectId
from datetime import datetime, timedelta
import logging
import io
import re
import urllib.parse
import utils
from translations import trans

logger = logging.getLogger(__name__)

# Placeholder functions for SMS/WhatsApp reminders (implement in utils.py or with external API)
def send_sms_reminder(recipient, message):
    """Placeholder for sending SMS reminder."""
    logger.info(f"Simulating SMS to {recipient}: {message}")
    return True, {'status': 'SMS sent successfully'}  # Replace with actual API call

def send_whatsapp_reminder(recipient, message):
    """Placeholder for sending WhatsApp reminder."""
    logger.info(f"Simulating WhatsApp to {recipient}: {message}")
    return True, {'status': 'WhatsApp sent successfully'}  # Replace with actual API call

class CreditorForm(FlaskForm):
    name = StringField(trans('creditors_creditor_name', default='Creditor Name'), validators=[DataRequired()])
    contact = StringField(trans('general_contact', default='Contact'), validators=[Optional()])
    amount_owed = FloatField(trans('creditors_amount_owed', default='Amount Owed'), validators=[DataRequired()])
    description = TextAreaField(trans('general_description', default='Description'), validators=[Optional()])
    submit = SubmitField(trans('creditors_add_creditor', default='Add Creditor'))

creditors_bp = Blueprint('creditors', __name__, url_prefix='/creditors')

@creditors_bp.route('/')
@login_required
@utils.requires_role('trader')
def index():
    """List all creditor records for the current user."""
    try:
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to view all creditors during testing
        # TODO: Restore original user_id filter {'user_id': str(current_user.id), 'type': 'creditor'} for production
        query = {'type': 'creditor'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'creditor'}
        creditors = list(db.records.find(query).sort('created_at', -1))
        
        return render_template(
            'creditors/index.html',
            creditors=creditors
        )
    except Exception as e:
        logger.error(f"Error fetching creditors for user {current_user.id}: {str(e)}")
        flash(trans('creditors_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@creditors_bp.route('/manage')
@login_required
@utils.requires_role('trader')
def manage():
    """List all creditor records for management (edit/delete) by the current user."""
    try:
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to view all creditors during testing
        # TODO: Restore original user_id filter for production
        query = {'type': 'creditor'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'creditor'}
        creditors = list(db.records.find(query).sort('created_at', -1))
        
        return render_template(
            'creditors/manage_creditors.html',
            creditors=creditors,
            format_currency=utils.format_currency,
            title=trans('creditors_manage_title', default='Manage Creditors', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching creditors for manage page for user {current_user.id}: {str(e)}")
        flash(trans('creditors_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('creditors.index'))

@creditors_bp.route('/view/<id>')
@login_required
@utils.requires_role('trader')
def view(id):
    """View detailed information about a specific creditor (JSON API)."""
    try:
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to view any creditor during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        if not creditor:
            return jsonify({'error': trans('creditors_record_not_found', default='Record not found')}), 404
        
        creditor['_id'] = str(creditor['_id'])
        creditor['created_at'] = creditor['created_at'].isoformat() if creditor.get('created_at') else None
        creditor['reminder_count'] = creditor.get('reminder_count', 0)
        
        return jsonify(creditor)
    except Exception as e:
        logger.error(f"Error fetching creditor {id} for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans('creditors_fetch_error', default='An error occurred')}), 500

@creditors_bp.route('/view_page/<id>')
@login_required
@utils.requires_role('trader')
def view_page(id):
    """Render a detailed view page for a specific creditor."""
    try:
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to view any creditor during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        if not creditor:
            flash(trans('creditors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('creditors.index'))
        
        return render_template(
            'creditors/view.html',
            creditor=creditor
        )
    except Exception as e:
        logger.error(f"Error rendering creditor view page {id} for user {current_user.id}: {str(e)}")
        flash(trans('creditors_view_error', default='An error occurred'), 'danger')
        return redirect(url_for('creditors.index'))

@creditors_bp.route('/share/<id>')
@login_required
@utils.requires_role('trader')
def share(id):
    """Generate a WhatsApp link to share IOU details."""
    try:
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to share any creditor during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        if not creditor:
            return jsonify({'success': False, 'message': trans('creditors_record_not_found', default='Record not found')}), 404
        if not creditor.get('contact'):
            return jsonify({'success': False, 'message': trans('creditors_no_contact', default='No contact provided for sharing')}), 400
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            return jsonify({'success': False, 'message': trans('debtors_insufficient_credits', default='Insufficient credits to share IOU')}), 400
        
        contact = re.sub(r'\D', '', creditor['contact'])
        if contact.startswith('0'):
            contact = '234' + contact[1:]
        elif not contact.startswith('+'):
            contact = '234' + contact
        
        message = f"Hi {creditor['name']}, this is an IOU for {utils.format_currency(creditor['amount_owed'])} recorded on FiCore Records on {utils.format_date(creditor['created_at'])}. Details: {creditor.get('description', 'No description provided')}."
        whatsapp_link = f"https://wa.me/{contact}?text={urllib.parse.quote(message)}"
        
        if not utils.is_admin():
            user_query = utils.get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"IOU shared for {creditor['name']} (Ficore Credits)"
            })
        
        return jsonify({'success': True, 'whatsapp_link': whatsapp_link})
    except Exception as e:
        logger.error(f"Error sharing IOU for creditor {id}: {str(e)}")
        return jsonify({'success': False, 'message': trans('creditors_share_error', default='An error occurred')}), 500

@creditors_bp.route('/send_reminder', methods=['POST'])
@login_required
@utils.requires_role('trader')
def send_reminder():
    """Send delivery reminder to creditor via SMS/WhatsApp or set snooze."""
    try:
        data = request.get_json()
        debt_id = data.get('debtId')
        recipient = data.get('recipient')
        message = data.get('message')
        send_type = data.get('type', 'sms')
        snooze_days = data.get('snooze_days', 0)
        
        if not debt_id or (not recipient and not snooze_days):
            return jsonify({'success': False, 'message': trans('creditors_missing_fields', default='Missing required fields')}), 400
        
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to send reminders for any creditor during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(debt_id), 'type': 'creditor'} if utils.is_admin() else {'_id': ObjectId(debt_id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        
        if not creditor:
            return jsonify({'success': False, 'message': trans('creditors_record_not_found', default='Record not found')}), 404
        
        credit_cost = 2 if recipient else 1
        if not utils.is_admin() and not utils.check_ficore_credit_balance(credit_cost):
            return jsonify({'success': False, 'message': trans('debtors_insufficient_credits', default='Insufficient credits to send reminder')}), 400
        
        update_data = {'$inc': {'reminder_count': 1}}
        if snooze_days:
            update_data['$set'] = {'reminder_date': datetime.utcnow() + timedelta(days=snooze_days)}
        
        success = True
        api_response = {}
        
        if recipient:
            if send_type == 'sms':
                success, api_response = send_sms_reminder(recipient, message)
            elif send_type == 'whatsapp':
                success, api_response = send_whatsapp_reminder(recipient, message)
        
        if success:
            db.records.update_one({'_id': ObjectId(debt_id)}, update_data)
            
            if not utils.is_admin():
                user_query = utils.get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -credit_cost}})
                db.ficore_credit_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -credit_cost,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"{'Reminder sent' if recipient else 'Snooze set'} for {creditor['name']} (Ficore Credits)"
                })
            
            db.reminder_logs.insert_one({
                'user_id': str(current_user.id),
                'debt_id': debt_id,
                'recipient': recipient or 'N/A',
                'message': message or 'Snooze',
                'type': send_type if recipient else 'snooze',
                'sent_at': datetime.utcnow(),
                'api_response': api_response if recipient else {'status': f'Snoozed for {snooze_days} days'}
            })
            
            return jsonify({'success': True, 'message': trans('creditors_reminder_sent' if recipient else 'creditors_snooze_set', default='Reminder sent successfully' if recipient else 'Snooze set successfully')})
        else:
            return jsonify({'success': False, 'message': trans('creditors_reminder_failed', default='Failed to send reminder'), 'details': api_response}), 500
            
    except Exception as e:
        logger.error(f"Error sending reminder: {str(e)}")
        return jsonify({'success': False, 'message': trans('creditors_reminder_error', default='An error occurred')}), 500

@creditors_bp.route('/generate_iou/<id>')
@login_required
@utils.requires_role('trader')
def generate_iou(id):
    """Generate PDF IOU for a creditor."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch
        
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to generate IOU for any creditor during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        
        if not creditor:
            flash(trans('creditors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('creditors.index'))
        
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            flash(trans('debtors_insufficient_credits', default='Insufficient credits to generate IOU'), 'danger')
            return redirect(url_for('credits.request_credits'))
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, height - inch, "FiCore Records - IOU")
        
        p.setFont("Helvetica", 12)
        y_position = height - inch - 0.5 * inch
        p.drawString(inch, y_position, f"Creditor: {creditor['name']}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Amount Owed: {utils.format_currency(creditor['amount_owed'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Contact: {creditor.get('contact', 'N/A')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Description: {creditor.get('description', 'No description provided')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Date Recorded: {utils.format_date(creditor['created_at'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Reminders Sent: {creditor.get('reminder_count', 0)}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, "This document serves as an IOU recorded on FiCore Records.")
        
        p.showPage()
        p.save()
        
        if not utils.is_admin():
            user_query = utils.get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"IOU generated for {creditor['name']} (Ficore Credits)"
            })
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_IOU_{creditor["name"]}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating IOU for creditor {id}: {str(e)}")
        flash(trans('creditors_iou_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('creditors.index'))

@creditors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role('trader')
def add():
    """Add a new creditor record."""
    form = CreditorForm()
    if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
        flash(trans('debtors_insufficient_credits', default='Insufficient credits to create a creditor. Request more credits.'), 'danger')
        return redirect(url_for('credits.request_credits'))
    if form.validate_on_submit():
        try:
            db = utils.get_mongo_db()
            record = {
                'user_id': str(current_user.id),
                'type': 'creditor',
                'name': form.name.data,
                'contact': form.contact.data,
                'amount_owed': form.amount_owed.data,
                'description': form.description.data,
                'reminder_count': 0,
                'created_at': datetime.utcnow()
            }
            db.records.insert_one(record)
            if not utils.is_admin():
                user_query = utils.get_user_query(str(current_user.id))
                db.users.update_one(
                    user_query,
                    {'$inc': {'ficore_credit_balance': -1}}
                )
                db.ficore_credit_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -1,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Creditor creation: {record['name']} (Ficore Credits)"
                })
            flash(trans('creditors_create_success', default='Creditor created successfully'), 'success')
            return redirect(url_for('creditors.index'))
        except Exception as e:
            logger.error(f"Error creating creditor for user {current_user.id}: {str(e)}")
            flash(trans('creditors_create_error', default='An error occurred'), 'danger')
    
    return render_template(
        'creditors/add.html',
        form=form
    )

@creditors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('trader')
def edit(id):
    """Edit an existing creditor record."""
    try:
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to edit any creditor during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        if not creditor:
            flash(trans('creditors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('creditors.index'))
        form = CreditorForm(data={
            'name': creditor['name'],
            'contact': creditor['contact'],
            'amount_owed': creditor['amount_owed'],
            'description': creditor['description']
        })
        if form.validate_on_submit():
            try:
                updated_record = {
                    'name': form.name.data,
                    'contact': form.contact.data,
                    'amount_owed': form.amount_owed.data,
                    'description': form.description.data,
                    'updated_at': datetime.utcnow()
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                flash(trans('creditors_edit_success', default='Creditor updated successfully'), 'success')
                return redirect(url_for('creditors.index'))
            except Exception as e:
                logger.error(f"Error updating creditor {id} for user {current_user.id}: {str(e)}")
                flash(trans('creditors_edit_error', default='An error occurred'), 'danger')
        
        return render_template(
            'creditors/edit.html',
            form=form,
            creditor=creditor
        )
    except Exception as e:
        logger.error(f"Error fetching creditor {id} for user {current_user.id}: {str(e)}")
        flash(trans('creditors_record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('creditors.index'))

@creditors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role('trader')
def delete(id):
    """Delete a creditor record."""
    try:
        db = utils.get_mongo_db()
        # TEMPORARY: Allow admin to delete any creditor during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        if not creditor:
            flash(trans('creditors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('creditors.index'))
        result = db.records.delete_one(query)
        if result.deleted_count:
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'creditor_id': str(creditor['_id']),
                'creditor_name': creditor['name'],
                'type': 'delete',
                'amount_change': 0,
                'date': datetime.utcnow(),
                'ref': f"Deleted creditor: {creditor['name']} (Ficore Credits)"
            })
            flash(trans('creditors_delete_success', default='Creditor deleted successfully'), 'success')
        else:
            flash(trans('creditors_record_not_found', default='Record not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting creditor {id} for user {current_user.id}: {str(e)}")
        flash(trans('creditors_delete_error', default='An error occurred'), 'danger')
    return redirect(url_for('creditors.index'))
