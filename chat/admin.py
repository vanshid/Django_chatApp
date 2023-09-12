from django.contrib import admin

from typing import List
from chat.models import Message



@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display:List[str] = ['id', 'thread_name', 'get_username', 'message', 'timestamp']
    list_per_page: int = 20

    def get_username(self, obj):
        return obj.sender.username if obj.sender else ''
