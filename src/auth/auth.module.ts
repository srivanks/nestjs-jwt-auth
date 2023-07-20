import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtService } from '@nestjs/jwt';
import { UsersModule } from 'src/users/users.module';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [UsersModule],
  controllers: [AuthController],
  providers: [AuthService, ConfigService, JwtService],
})
export class AuthModule {}
