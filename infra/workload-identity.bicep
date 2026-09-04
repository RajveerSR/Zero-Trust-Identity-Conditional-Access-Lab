@description('Short lowercase prefix used in globally unique resource names.')
@minLength(3)
@maxLength(8)
param namePrefix string = 'ztidlab'

@description('Azure region for the managed identity and storage account.')
param location string = resourceGroup().location

var storageName = toLower('${namePrefix}${uniqueString(resourceGroup().id)}')
var blobDataReaderRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
)

resource probeIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-probe-mi'
  location: location
  tags: {
    lab: 'zero-trust-identity'
    purpose: 'container-scoped-read-probe'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: false
    }
  }
}

resource allowedContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'allowed'
  properties: {
    publicAccess: 'None'
  }
}

resource deniedContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'denied'
  properties: {
    publicAccess: 'None'
  }
}

resource allowedReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(allowedContainer.id, probeIdentity.id, blobDataReaderRoleId)
  scope: allowedContainer
  properties: {
    principalId: probeIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: blobDataReaderRoleId
  }
}

output managedIdentityClientId string = probeIdentity.properties.clientId
output managedIdentityPrincipalId string = probeIdentity.properties.principalId
output managedIdentityResourceId string = probeIdentity.id
output storageAccountName string = storage.name
output allowedContainerScope string = allowedContainer.id
output deniedContainerScope string = deniedContainer.id
