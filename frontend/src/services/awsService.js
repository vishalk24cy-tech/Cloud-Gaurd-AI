import api from "./api";


// ============================================================
// CONNECT AWS ACCOUNT
// ============================================================

export const connectAWS = async (data) => {

    const response = await api.post(
        "/aws/connect",
        data
    );

    return response.data;
};


// ============================================================
// GET CONNECTED AWS ACCOUNTS
// ============================================================

export const getAWSAccounts = async () => {

    const response = await api.get(
        "/aws/accounts"
    );

    return response.data.accounts || [];
};


// ============================================================
// GET SINGLE AWS ACCOUNT
// ============================================================

export const getAWSAccount = async (accountId) => {

    const response = await api.get(
        `/aws/account/${accountId}`
    );

    return response.data;
};


// ============================================================
// DELETE AWS ACCOUNT
// ============================================================

export const deleteAWSAccount = async (accountId) => {

    const response = await api.delete(
        `/aws/account/${accountId}`
    );

    return response.data;
};


// ============================================================
// RUN AWS SECURITY SCAN
// ============================================================

export const scanAWS = async (accountId) => {

    const response = await api.get(
        `/aws/scan/${accountId}`,
        {
            timeout: 120000
        }
    );

    return response.data;
};


// ============================================================
// GET EC2 INSTANCES INVENTORY (READ-ONLY)
// ============================================================

export const getEC2Instances = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/ec2/${accountId}/instances`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// EC2 RESOURCE CONTROL ACTIONS (START / STOP / REBOOT)
// ============================================================

export const controlEC2Instance = async (
    accountId,
    instanceId,
    { action, region, confirmed = true }
) => {
    const response = await api.post(
        `/cloud/aws/ec2/${accountId}/instances/${instanceId}/action`,
        {
            action,
            region,
            confirmed,
        }
    );

    return response.data;
};


// ============================================================
// GET S3 BUCKETS INVENTORY & SECURITY POSTURE (READ-ONLY)
// ============================================================

export const getS3Buckets = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/s3/${accountId}/buckets`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// S3 RESOURCE CONTROL ACTIONS (ENABLE BPA / ENCRYPTION / VERSIONING)
// ============================================================

export const controlS3Bucket = async (
    accountId,
    bucketName,
    { action, region, confirmed = true }
) => {
    const response = await api.post(
        `/cloud/aws/s3/${accountId}/buckets/${bucketName}/action`,
        {
            action,
            region,
            confirmed,
        }
    );

    return response.data;
};


// ============================================================
// GET RDS INSTANCES INVENTORY (READ-ONLY)
// ============================================================

export const getRDSInstances = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/rds/${accountId}/instances`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// GET RDS CLUSTERS INVENTORY (READ-ONLY)
// ============================================================

export const getRDSClusters = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/rds/${accountId}/clusters`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// RDS RESOURCE CONTROL ACTIONS (START / STOP / REBOOT / SECURITY)
// ============================================================

export const controlRDSInstance = async (
    accountId,
    instanceId,
    { action, region, confirmed = true }
) => {
    const response = await api.post(
        `/cloud/aws/rds/${accountId}/instances/${instanceId}/action`,
        {
            action,
            region,
            confirmed,
        }
    );

    return response.data;
};


// ============================================================
// GET VPCs INVENTORY (READ-ONLY)
// ============================================================

export const getVPCs = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/network/${accountId}/vpcs`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// GET SUBNETS INVENTORY (READ-ONLY)
// ============================================================

export const getSubnets = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/network/${accountId}/subnets`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// GET SECURITY GROUPS INVENTORY & SECURITY POSTURE (READ-ONLY)
// ============================================================

export const getSecurityGroups = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/network/${accountId}/security-groups`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// GET ROUTE TABLES INVENTORY (READ-ONLY)
// ============================================================

export const getRouteTables = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/network/${accountId}/route-tables`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// GET GATEWAYS INVENTORY (READ-ONLY)
// ============================================================

export const getGateways = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/network/${accountId}/gateways`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// GET VPC ENDPOINTS INVENTORY (READ-ONLY)
// ============================================================

export const getVPCEndpoints = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/network/${accountId}/endpoints`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// SECURITY GROUP CONTROL / REMEDIATION ACTIONS (REVOKE INSECURE RULES)
// ============================================================

export const controlSecurityGroup = async (
    accountId,
    groupId,
    { action, region, rule_spec, confirmed = true }
) => {
    const response = await api.post(
        `/cloud/aws/network/${accountId}/security-groups/${groupId}/action`,
        {
            action,
            region,
            rule_spec,
            confirmed,
        }
    );

    return response.data;
};


// ============================================================
// GET IAM INVENTORY (READ-ONLY)
// ============================================================

export const getIAMInventory = async (accountId, params = {}) => {
    const response = await api.get(
        `/cloud/aws/iam/${accountId}/inventory`,
        {
            params,
        }
    );

    return response.data;
};


// ============================================================
// IAM RESOURCE CONTROL ACTIONS
// ============================================================

export const controlIAMResource = async (
    accountId,
    resourceId,
    { action, resource_type, parameters, confirmed = true }
) => {
    const response = await api.post(
        `/cloud/aws/iam/${accountId}/resources/${resourceId}/action`,
        {
            action,
            resource_type,
            parameters,
            confirmed,
        }
    );

    return response.data;
};