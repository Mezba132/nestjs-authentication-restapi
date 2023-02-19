import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { SignUpDto, SignInDto } from './dto';
import { AuthService } from './auth.service';
import { Tokens } from './types';
import { GetCurrentUser, GetCurrentUserId, Public } from './decorators';
import { RtGuard } from './guards';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body() body: SignUpDto): Promise<any> {
    return await this.authService.signUp(body);
  }

  @Public()
  @Post('signin')
  @HttpCode(HttpStatus.OK)
  async signIn(@Body() body: SignInDto): Promise<Tokens> {
    return await this.authService.signIn(body);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@GetCurrentUserId() userId: number): Promise<boolean> {
    return await this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ): Promise<Tokens> {
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @Get('users')
  @HttpCode(HttpStatus.OK)
  getUers(): Promise<any> {
    return this.authService.getUsers();
  }
}
