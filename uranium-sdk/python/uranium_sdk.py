"""
Uranium SDK - Python client library for Uranium Vault

This SDK provides a simple interface to interact with the Uranium Vault server
for secure model storage and retrieval.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any
import json
import requests
from uuid import UUID


class ModelFormat(Enum):
    """Model storage format"""
    SAFETENSORS = "SafeTensors"
    ONNX = "ONNX"
    PYTORCH = "PyTorch"
    TENSORFLOW = "TensorFlow"
    UNKNOWN = "Unknown"


@dataclass
class ModelInfo:
    """Model information"""
    id: UUID
    name: str
    size: int
    encrypted_with_se: bool
    created_at: datetime


@dataclass
class VaultStatus:
    """Vault status information"""
    vault_status: str
    secure_enclave_available: bool
    secure_enclave_enabled: bool
    models_count: int


class VaultClient:
    """Uranium Vault client"""
    
    def __init__(self, base_url: str, timeout: int = 300):
        """
        Initialize vault client
        
        Args:
            base_url: Base URL of the vault server
            timeout: Request timeout in seconds (default: 300)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.token: Optional[str] = None
        self.session = requests.Session()
    
    def authenticate(self, username: str, password: str) -> str:
        """
        Authenticate with the vault
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Authentication token
        """
        resp = self._post('/api/v1/auth/login', {
            'username': username,
            'password': password
        })
        
        self.token = resp['token']
        return self.token
    
    def store_model(self, name: str, data: bytes, format: ModelFormat) -> UUID:
        """
        Store a model in the vault
        
        Args:
            name: Model name
            data: Model data as bytes
            format: Model format
            
        Returns:
            Model ID
        """
        self._require_auth()
        
        # Convert bytes to list of integers for JSON serialization
        data_list = list(data)
        
        resp = self._post('/api/v1/models', {
            'name': name,
            'data': data_list,
            'format': format.value
        })
        
        return UUID(resp['id'])
    
    def store_model_from_file(self, path: Path, name: str, format: ModelFormat) -> UUID:
        """
        Store a model from file
        
        Args:
            path: Path to model file
            name: Model name
            format: Model format
            
        Returns:
            Model ID
        """
        with open(path, 'rb') as f:
            data = f.read()
        
        return self.store_model(name, data, format)
    
    def list_models(self) -> List[ModelInfo]:
        """
        List all models
        
        Returns:
            List of model information
        """
        self._require_auth()
        
        resp = self._get('/api/v1/models')
        return [self._parse_model_info(m) for m in resp]
    
    def get_model(self, model_id: UUID) -> ModelInfo:
        """
        Get model metadata
        
        Args:
            model_id: Model ID
            
        Returns:
            Model information
        """
        self._require_auth()
        
        resp = self._get(f'/api/v1/models/{model_id}')
        return self._parse_model_info(resp)
    
    def load_model(self, model_id: UUID) -> bytes:
        """
        Load model data
        
        Args:
            model_id: Model ID
            
        Returns:
            Model data as bytes
        """
        self._require_auth()
        
        # Note: This would need the actual download endpoint
        # For now, returning empty bytes as placeholder
        return b''
    
    def delete_model(self, model_id: UUID) -> None:
        """
        Delete a model
        
        Args:
            model_id: Model ID
        """
        self._require_auth()
        
        self._delete(f'/api/v1/models/{model_id}')
    
    def status(self) -> VaultStatus:
        """
        Get vault status
        
        Returns:
            Vault status information
        """
        resp = self._get('/api/v1/status')
        
        return VaultStatus(
            vault_status=resp['vault_status'],
            secure_enclave_available=resp['secure_enclave_available'],
            secure_enclave_enabled=resp['secure_enclave_enabled'],
            models_count=resp['models_count']
        )
    
    # Helper methods
    
    def _require_auth(self):
        """Ensure client is authenticated"""
        if not self.token:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
    
    def _get(self, path: str) -> Any:
        """Make GET request"""
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        resp = self.session.get(
            f'{self.base_url}{path}',
            headers=headers,
            timeout=self.timeout
        )
        
        return self._handle_response(resp)
    
    def _post(self, path: str, data: Dict[str, Any]) -> Any:
        """Make POST request"""
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        resp = self.session.post(
            f'{self.base_url}{path}',
            headers=headers,
            json=data,
            timeout=self.timeout
        )
        
        return self._handle_response(resp)
    
    def _delete(self, path: str) -> None:
        """Make DELETE request"""
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        resp = self.session.delete(
            f'{self.base_url}{path}',
            headers=headers,
            timeout=self.timeout
        )
        
        self._handle_response(resp)
    
    def _handle_response(self, resp: requests.Response) -> Any:
        """Handle HTTP response"""
        if resp.status_code >= 400:
            try:
                error = resp.json()
                raise RuntimeError(f"API error: {error.get('error', 'Unknown error')}")
            except json.JSONDecodeError:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
        
        if resp.status_code == 204:  # No content
            return None
        
        return resp.json()
    
    def _parse_model_info(self, data: Dict[str, Any]) -> ModelInfo:
        """Parse model info from API response"""
        return ModelInfo(
            id=UUID(data['id']),
            name=data['name'],
            size=data['size'],
            encrypted_with_se=data['encrypted_with_se'],
            created_at=datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        )


# Convenience functions

def connect(base_url: str, username: str, password: str) -> VaultClient:
    """
    Connect to vault and authenticate
    
    Args:
        base_url: Vault server URL
        username: Username
        password: Password
        
    Returns:
        Authenticated vault client
    """
    client = VaultClient(base_url)
    client.authenticate(username, password)
    return client