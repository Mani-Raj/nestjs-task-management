import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthCredentialDto } from './dto/auth-credentials.dto';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(private authservice: AuthService) {

    }

    @Post('/signup')
    signUp(@Body() authCredentialDto: AuthCredentialDto): Promise<void> {
        return this.authservice.signUp(authCredentialDto)
    }

    @Post('/signin')
    signIp(@Body() authCredentialDto: AuthCredentialDto): Promise<{ accessToken: string }> {
        return this.authservice.signIn(authCredentialDto)
    }

    /**
     * 
     * @param req - Test route to check guards/jwt authentication
     */
    @Post('/test')
    @UseGuards(AuthGuard())
    test(@Req() req) {
        console.log(req)
    }

}
