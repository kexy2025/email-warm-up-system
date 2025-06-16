import random
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText, MIMEMultipart
import smtplib
import ssl
from typing import List, Dict, Optional
import logging
from dataclasses import dataclass
import uuid

logger = logging.getLogger(__name__)

@dataclass
class WarmupEmail:
    """Email data structure for warmup campaigns."""
    sender: str
    recipient: str
    subject: str
    content: str
    campaign_id: int
    send_time: datetime
    email_type: str = 'warmup'

class EmailWarmupService:
    """Service for managing email warmup campaigns."""
    
    def __init__(self, db, campaign_model, email_log_model, metrics_model):
        self.db = db
        self.campaign_model = campaign_model
        self.email_log_model = email_log_model
        self.metrics_model = metrics_model
        
        # Warmup email templates
        self.email_templates = self._load_email_templates()
        
        # Temporary email pool for replies
        self.temp_email_pool = [
            'warmup1@tempmail.example.com',
            'warmup2@tempmail.example.com',
            'warmup3@tempmail.example.com',
            'warmup4@tempmail.example.com',
            'warmup5@tempmail.example.com',
        ]
    
    def generate_warmup_emails(self, campaign_id: int, daily_volume: int) -> List[WarmupEmail]:
        """Generate warmup emails for a campaign."""
        try:
            campaign = self.campaign_model.query.get(campaign_id)
            if not campaign:
                raise ValueError(f"Campaign {campaign_id} not found")
            
            emails = []
            current_time = datetime.utcnow()
            
            # Calculate send times throughout the day
            send_intervals = self._calculate_send_intervals(daily_volume)
            
            for i in range(daily_volume):
                # Select random recipient from temp pool
                recipient = random.choice(self.temp_email_pool)
                
                # Generate email content
                template = random.choice(self.email_templates)
                subject, content = self._personalize_template(template, campaign.email_address)
                
                # Calculate send time
                send_time = current_time + timedelta(minutes=send_intervals[i])
                
                email = WarmupEmail(
                    sender=campaign.email_address,
                    recipient=recipient,
                    subject=subject,
                    content=content,
                    campaign_id=campaign_id,
                    send_time=send_time
                )
                
                emails.append(email)
            
            logger.info(f"Generated {len(emails)} warmup emails for campaign {campaign_id}")
            return emails
            
        except Exception as e:
            logger.error(f"Error generating warmup emails: {str(e)}")
            raise
    
    def send_warmup_email(self, email: WarmupEmail) -> Dict:
        """Send a single warmup email."""
        try:
            campaign = self.campaign_model.query.get(email.campaign_id)
            if not campaign:
                raise ValueError(f"Campaign {email.campaign_id} not found")
            
            # Decrypt SMTP password
            smtp_password = campaign.decrypt_password()
            if not smtp_password:
                raise ValueError("SMTP password not found or cannot be decrypted")
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['From'] = email.sender
            msg['To'] = email.recipient
            msg['Subject'] = email.subject
            msg['Message-ID'] = f"<{uuid.uuid4()}@{email.sender.split('@')[1]}>"
            msg['Date'] = email.send_time.strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            # Add content
            text_part = MIMEText(email.content, 'plain')
            msg.attach(text_part)
            
            # Send email
            result = self._send_smtp_email(
                msg, 
                campaign.smtp_host, 
                campaign.smtp_port,
                campaign.smtp_username or campaign.email_address,
                smtp_password
            )
            
            # Log email
            self._log_email_sent(email, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error sending warmup email: {str(e)}")
            error_result = {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow()
            }
            self._log_email_sent(email, error_result)
            return error_result
    
    def process_campaign_warmup(self, campaign_id: int) -> Dict:
        """Process warmup for a specific campaign."""
        try:
            campaign = self.campaign_model.query.get(campaign_id)
            if not campaign or campaign.status != 'active':
                return {'error': 'Campaign not found or not active'}
            
            # Calculate current daily volume based on campaign progress
            days_active = (datetime.utcnow() - campaign.started_at).days
            current_volume = self._calculate_current_volume(campaign.daily_volume, days_active)
            current_volume = min(current_volume, campaign.max_volume)
            
            # Generate and send emails
            emails = self.generate_warmup_emails(campaign_id, current_volume)
            results = []
            
            for email in emails:
                # Add random delay between sends (1-5 minutes)
                delay = random.randint(60, 300)
                time.sleep(delay)
                
                result = self.send_warmup_email(email)
                results.append(result)
                
                # Break if we encounter too many errors
                if len([r for r in results if not r.get('success', False)]) > current_volume * 0.3:
                    logger.warning(f"Too many failures for campaign {campaign_id}, stopping")
                    break
            
            # Update campaign metrics
            self._update_campaign_metrics(campaign_id, results)
            
            return {
                'campaign_id': campaign_id,
                'emails_processed': len(results),
                'emails_sent': len([r for r in results if r.get('success', False)]),
                'errors': len([r for r in results if not r.get('success', False)]),
                'current_volume': current_volume
            }
            
        except Exception as e:
            logger.error(f"Error processing campaign warmup: {str(e)}")
            return {'error': str(e)}
    
    def _send_smtp_email(self, msg, smtp_host, smtp_port, smtp_username, smtp_password):
        """Send email via SMTP."""
        try:
            if smtp_port == 465:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port)
                server.starttls()
            
            server.login(smtp_username, smtp_password)
            result = server.send_message(msg)
            server.quit()
            
            return {
                'success': True,
                'timestamp': datetime.utcnow(),
                'smtp_response': str(result)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow()
            }
    
    def _log_email_sent(self, email: WarmupEmail, result: Dict):
        """Log sent email to database."""
        try:
            log_entry = self.email_log_model(
                sender_email=email.sender,
                recipient_email=email.recipient,
                subject=email.subject,
                status='sent' if result.get('success') else 'failed',
                smtp_response=result.get('smtp_response') or result.get('error'),
                campaign_id=email.campaign_id,
                sent_at=result.get('timestamp', datetime.utcnow())
            )
            
            self.db.session.add(log_entry)
            self.db.session.commit()
            
        except Exception as e:
            logger.error(f"Error logging email: {str(e)}")
            self.db.session.rollback()
    
    def _update_campaign_metrics(self, campaign_id: int, results: List[Dict]):
        """Update campaign metrics."""
        try:
            today = datetime.utcnow().date()
            
            # Get or create metrics for today
            metrics = self.metrics_model.query.filter_by(
                campaign_id=campaign_id,
                date=today
            ).first()
            
            if not metrics:
                metrics = self.metrics_model(
                    campaign_id=campaign_id,
                    date=today
                )
                self.db.session.add(metrics)
            
            # Update metrics
            successful_sends = len([r for r in results if r.get('success', False)])
            failed_sends = len([r for r in results if not r.get('success', False)])
            
            metrics.emails_sent += len(results)
            metrics.emails_delivered += successful_sends
            metrics.emails_bounced += failed_sends
            
            # Calculate reputation score (simple algorithm)
            if metrics.emails_sent > 0:
                success_rate = metrics.emails_delivered / metrics.emails_sent
                metrics.reputation_score = min(100, success_rate * 100)
            
            self.db.session.commit()
            
        except Exception as e:
            logger.error(f"Error updating metrics: {str(e)}")
            self.db.session.rollback()
    
    def _calculate_send_intervals(self, daily_volume: int) -> List[int]:
        """Calculate send intervals throughout the day."""
        # Spread emails over 8-hour business day (480 minutes)
        base_interval = 480 // daily_volume if daily_volume > 0 else 480
        
        intervals = []
        current_time = 0
        
        for i in range(daily_volume):
            # Add some randomness to avoid pattern detection
            variance = random.randint(-base_interval//4, base_interval//4)
            interval = max(5, base_interval + variance)  # Minimum 5 minutes between emails
            
            current_time += interval
            intervals.append(current_time)
        
        return intervals
    
    def _calculate_current_volume(self, initial_volume: int, days_active: int) -> int:
        """Calculate current daily volume based on warmup progression."""
        # Gradual increase: +1 email every 3 days
        volume_increase = days_active // 3
        return initial_volume + volume_increase
    
    def _load_email_templates(self) -> List[Dict]:
        """Load email templates for warmup campaigns."""
        return [
            {
                'category': 'business_inquiry',
                'subject_templates': [
                    'Quick question about your services',
                    'Interested in learning more',
                    'Partnership opportunity',
                    'Following up on our conversation',
                    'Question about your products'
                ],
                'content_templates': [
                    """Hi there,

I hope this email finds you well. I came across your company and was impressed by what I saw.

I'd love to learn more about your services and how we might be able to work together in the future.

Would you be available for a brief call this week?

Best regards,
{sender_name}""",
                    """Hello,

I'm reaching out because I'm interested in your products/services.

Could you please send me more information about your offerings?

Thank you for your time.

Best,
{sender_name}"""
                ]
            },
            {
                'category': 'follow_up',
                'subject_templates': [
                    'Following up on my previous email',
                    'Just checking in',
                    'Any updates?',
                    'Circling back',
                    'Quick follow-up'
                ],
                'content_templates': [
                    """Hi,

I wanted to follow up on my previous email. 

Please let me know if you need any additional information from my end.

Looking forward to hearing from you.

Best,
{sender_name}""",
                    """Hello,

Just wanted to check if you had a chance to review my previous message.

No pressure - just wanted to make sure it didn't get lost in your inbox.

Thanks!
{sender_name}"""
                ]
            },
            {
                'category': 'networking',
                'subject_templates': [
                    'Great meeting you at [Event]',
                    'Connecting as discussed',
                    'Nice to meet you',
                    'Following up from [Event]',
                    'Let\'s stay in touch'
                ],
                'content_templates': [
                    """Hi {recipient_name},

It was great meeting you at the conference last week. I really enjoyed our conversation about industry trends.

I'd love to continue our discussion sometime. Are you free for coffee next week?

Best regards,
{sender_name}""",
                    """Hello,

I hope you're doing well. It was a pleasure meeting you recently.

I thought you might be interested in this article I came across: [link]

Looking forward to staying in touch.

Best,
{sender_name}"""
                ]
            }
        ]
    
    def _personalize_template(self, template: Dict, sender_email: str) -> tuple:
        """Personalize email template with sender information."""
        # Extract sender name from email
        sender_name = sender_email.split('@')[0].replace('.', ' ').title()
        
        # Select random subject and content
        subject = random.choice(template['subject_templates'])
        content = random.choice(template['content_templates'])
        
        # Personalize content
        content = content.replace('{sender_name}', sender_name)
        content = content.replace('{recipient_name}', 'there')  # Generic for warmup
        
        # Add some variation to subject
        if '[Event]' in subject:
            events = ['the conference', 'the networking event', 'the seminar', 'the workshop']
            subject = subject.replace('[Event]', random.choice(events))
        
        return subject, content

# Global service instance (to be initialized with app context)
warmup_service = None

def init_warmup_service(db, campaign_model, email_log_model, metrics_model):
    """Initialize the warmup service."""
    global warmup_service
    warmup_service = EmailWarmupService(db, campaign_model, email_log_model, metrics_model)
    return warmup_service
