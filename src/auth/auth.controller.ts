import { Controller, Get, Post, Body, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';

import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { AccessTokenGuard } from 'src/common/guards/accessTokens.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signUp(@Body() createUserDto: CreateUserDto) {
    console.log(createUserDto);
    return this.authService.signUp(createUserDto);
  }

  @Post('signin')
  signIn(@Body() data: CreateAuthDto) {
    return this.authService.signIn(data);
  }

  @Get('logout')
  @UseGuards(AccessTokenGuard)
  logout(@Req() req: Request) {
    this.authService.logout(req.user['sub']);
  }
}
