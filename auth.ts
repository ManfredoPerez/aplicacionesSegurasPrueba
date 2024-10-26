//auth.ts
import { hash, verify } from 'argon2';
import { sign, verify as jwtVerify } from 'jsonwebtoken';
import { randomBytes } from 'crypto';

interface User {
  id: string;
  role: 'admin' | 'doctor' | 'nurse';
  permissions: string[];
}

export class SecurityService {
  private readonly JWT_SECRET = process.env.JWT_SECRET!;
  private readonly PEPPER = process.env.PEPPER!;

  // Función para hash seguro de contraseñas
  async hashPassword(password: string): Promise<string> {
    const salt = randomBytes(32);
    const peppered = `${password}${this.PEPPER}`;
    return await hash(peppered, {
      salt,
      type: 2,
      memoryCost: 65536,
      timeCost: 4,
      parallelism: 2
    });
  }

  // Verificación segura de contraseñas
  async verifyPassword(hash: string, password: string): Promise<boolean> {
    const peppered = `${password}${this.PEPPER}`;
    return await verify(hash, peppered);
  }

  // Generación de token JWT seguro
  generateToken(user: User): string {
    return sign(
      {
        id: user.id,
        role: user.role,
        permissions: user.permissions
      },
      this.JWT_SECRET,
      {
        expiresIn: '1h',
        algorithm: 'ES256'
      }
    );
  }

  // Middleware de autorización basado en roles
  authorizeRole(allowedRoles: string[]) {
    return (req: any, res: any, next: any) => {
      try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
          return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwtVerify(token, this.JWT_SECRET) as User;
        if (!allowedRoles.includes(decoded.role)) {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }

        req.user = decoded;
        next();
      } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    };
  }
}

// src/security/encryption.ts
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

export class EncryptionService {
  private readonly ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY!, 'base64');
  private readonly ALGORITHM = 'aes-256-gcm';

  // Cifrado de datos sensibles
  encrypt(data: string): { encryptedData: string; iv: string; tag: string } {
    const iv = randomBytes(12);
    const cipher = createCipheriv(this.ALGORITHM, this.ENCRYPTION_KEY, iv);
    
    let encryptedData = cipher.update(data, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    
    return {
      encryptedData,
      iv: iv.toString('hex'),
      tag: cipher.getAuthTag().toString('hex')
    };
  }

  // Descifrado de datos
  decrypt(encryptedData: string, iv: string, tag: string): string {
    const decipher = createDecipheriv(
      this.ALGORITHM,
      this.ENCRYPTION_KEY,
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}

// src/security/audit.ts
import { createLogger, format, transports } from 'winston';

export class AuditService {
  private logger = createLogger({
    level: 'info',
    format: format.combine(
      format.timestamp(),
      format.json()
    ),
    transports: [
      new transports.File({ filename: 'audit.log' }),
      new transports.Console()
    ]
  });

  // Registro de eventos de auditoría
  logAuditEvent(event: {
    userId: string;
    action: string;
    resource: string;
    details: any;
  }) {
    this.logger.info('Audit Event', {
      timestamp: new Date().toISOString(),
      ...event,
      ip: this.getClientIP(),
      userAgent: this.getUserAgent()
    });
  }

  private getClientIP() {
    // Implementación para obtener IP del cliente
    return '';
  }

  private getUserAgent() {
    // Implementación para obtener User Agent
    return '';
  }
}

// src/security/validation.ts
import { z } from 'zod';

export const PatientSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(2).max(100),
  dateOfBirth: z.string().datetime(),
  socialSecurityNumber: z.string().regex(/^\d{3}-\d{2}-\d{4}$/),
  medicalRecordNumber: z.string(),
  consent: z.boolean()
});

export const TreatmentSchema = z.object({
  id: z.string().uuid(),
  patientId: z.string().uuid(),
  type: z.string(),
  startDate: z.string().datetime(),
  endDate: z.string().datetime().optional(),
  notes: z.string().max(1000),
  prescribedBy: z.string().uuid()
});

// src/security/consent.ts
export class ConsentManager {
  // Gestión de consentimientos GDPR
  async recordConsent(
    patientId: string,
    purpose: string,
    granted: boolean
  ): Promise<void> {
    const consentRecord = {
      patientId,
      purpose,
      granted,
      timestamp: new Date(),
      version: '1.0'
    };

    // Almacenar consentimiento y generar evidencia
    await this.storeConsent(consentRecord);
    await this.generateConsentReceipt(consentRecord);
  }

  private async storeConsent(consentRecord: any): Promise<void> {
    // Implementación del almacenamiento
  }

  private async generateConsentReceipt(consentRecord: any): Promise<void> {
    // Implementación de la generación del recibo
  }
}