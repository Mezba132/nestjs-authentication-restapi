import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtModule } from '@nestjs/jwt';
import { AtStrategy } from './strategies';
import { RtStrategy } from './strategies/refresh-token.strategy';

@Module({
  imports: [JwtModule.register({})],
  providers: [AuthService, PrismaService, AtStrategy, RtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
