from django.core.management.base import BaseCommand
import os
import warnings

class Command(BaseCommand):
    help = 'Regenerate AI-WAF model with current scikit-learn version'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force regeneration even if model exists',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("🔄 AI-WAF Model Regeneration"))
        self.stdout.write("")
        
        # Check current sklearn version
        try:
            import sklearn
            self.stdout.write(f"Current scikit-learn version: {sklearn.__version__}")
        except ImportError:
            self.stdout.write(self.style.ERROR("❌ scikit-learn not available"))
            self.stdout.write("Install with: pip install scikit-learn")
            return
        
        # Check if model exists
        from aiwaf.trainer import MODEL_PATH
        model_exists = os.path.exists(MODEL_PATH)
        
        if model_exists and not options['force']:
            self.stdout.write(f"Model exists at: {MODEL_PATH}")
            
            # Try to load and check version
            try:
                import joblib
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.base")
                    model_data = joblib.load(MODEL_PATH)
                    
                if isinstance(model_data, dict) and 'sklearn_version' in model_data:
                    stored_version = model_data['sklearn_version']
                    if stored_version == sklearn.__version__:
                        self.stdout.write(self.style.SUCCESS("✅ Model is up-to-date"))
                        return
                    else:
                        self.stdout.write(f"⚠️  Model version mismatch:")
                        self.stdout.write(f"   Stored: {stored_version}")
                        self.stdout.write(f"   Current: {sklearn.__version__}")
                else:
                    self.stdout.write("⚠️  Legacy model format detected")
                    
            except Exception as e:
                self.stdout.write(f"⚠️  Could not check model: {e}")
            
            self.stdout.write("")
            self.stdout.write("Regenerating model to fix version compatibility...")
        
        # Regenerate model
        self.stdout.write("🚀 Starting model training...")
        
        try:
            from aiwaf.trainer import train
            train()
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS("✅ Model regenerated successfully!"))
            self.stdout.write("")
            self.stdout.write("The model is now compatible with your current scikit-learn version.")
            self.stdout.write("Version warnings should no longer appear.")
            
        except Exception as e:
            self.stdout.write("")
            self.stdout.write(self.style.ERROR(f"❌ Model regeneration failed: {e}"))
            self.stdout.write("")
            self.stdout.write("Possible solutions:")
            self.stdout.write("1. Check that you have log data available")
            self.stdout.write("2. Verify AIWAF_ACCESS_LOG setting")
            self.stdout.write("3. Run 'python manage.py detect_and_train' for full training")
