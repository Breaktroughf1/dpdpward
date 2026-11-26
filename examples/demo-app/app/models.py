from django.db import models


class KycDocument(models.Model):
    customer_id = models.BigIntegerField()
    selfie = models.ImageField(upload_to="kyc/")
    face_embedding = models.BinaryField()
    verified_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "kyc_documents"
