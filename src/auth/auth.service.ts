import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { SignInDto, SignUpDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtPayload, Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
const bcrypt = require('bcryptjs');

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private config: ConfigService,
    private prismaService: PrismaService,
  ) {}

  signUp = async (body: SignUpDto): Promise<any> => {
    const salt = bcrypt.genSaltSync(10);
    body.password = bcrypt.hashSync(body.password, salt);
    let registeredUser = await this.prismaService.user
      .create({
        data: {
          email: body.email,
          password: body.password,
          name: body.name,
        },
      })
      .catch(() => {
        throw new UnauthorizedException('incorrect Credentials');
      });
    return {
      id: registeredUser.id,
      email: registeredUser.email,
    };
  };

  signIn = async (body: SignInDto) => {
    const user: any = await this.prismaService.user.findUnique({
      where: {
        email: body.email,
      },
    });

    if (!user) throw new ForbiddenException('Access Denied');
    const passwordMatches = await bcrypt.compareSync(
      body.password,
      user.password,
    );
    if (!passwordMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  };

  logout = async (userId: number): Promise<boolean> => {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        refreshToken: {
          not: null,
        },
      },
      data: {
        refreshToken: null,
      },
    });
    return true;
  };

  refreshTokens = async (
    userId: number,
    refreshToken: string,
  ): Promise<Tokens> => {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.refreshToken)
      throw new ForbiddenException('Access Denied');

    const refreshTokenMatches = await bcrypt.compareSync(
      refreshToken,
      user.refreshToken,
    );
    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  };

  updateRtHash = async (userId: number, rt: string): Promise<void> => {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(rt, salt);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: hash,
      },
    });
  };

  getTokens = async (userId: number, email: string): Promise<Tokens> => {
    const jwtPayload: JwtPayload = {
      id: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  };

  getUsers = async () => {
    let users = await this.prismaService.user.findMany();
    return users;
  };
}
