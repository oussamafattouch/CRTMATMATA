from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate


# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email','first_name','last_name','password')
        extra_kwargs = {'password': {'write_only': True}}

       
    def create(self, validated_data):
        user = User.objects.create_user(username=validated_data['username'], email=validated_data['email'],first_name=validated_data['first_name'],last_name= validated_data['last_name'],password=validated_data['password'])
       

        return user

class LoginUserSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=100,
        style={'placeholder': 'Email', 'autofocus': True}
    )
    password = serializers.CharField(
        max_length=100,
        style={'input_type': 'password', 'placeholder': 'Password'}
    )

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid Details.")