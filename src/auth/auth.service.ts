import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService{
    constructor(
        private prisma: PrismaService, 
        private jwt: JwtService,
        private config: ConfigService
        ) {}      

    async signup(dto: AuthDto) {
        // generate the password hash
        const hash = await argon.hash(dto.password);
        //save the new user in the db

        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
                /*select: {
                    id: true,
                    email: true,
                    createdAt: true,
                }*/
            });
            // delete user.hash;
            //return the saved user
            return this.signToken(user.id, user.email);
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if(error.code === 'P2002') {
                    throw new ForbiddenException('Credentials already taken');
                }
            }
        }
    }

    async login(dto: AuthDto) {

        // find the user by email
        // if not found, throw an error
        // if found, compare the password hash with the hash in the db
        // if not equal, throw an error
        // if equal, return the user
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            }
        });

        if(!user) {
            throw new ForbiddenException('Credentials Incorrect');
        }
        const isValid = await argon.verify(user.hash, dto.password);
        if(!isValid) {
            throw new ForbiddenException('Credentials Incorrect');
        }
        
        return this.signToken(user.id, user.email);
    }

    async signToken(userId: number, email: string) : Promise<{ access_token : string}> {
        const payload = {
            sub: userId,
            email,
        };
        const secret = this.config.get('JWT_SECRET');
        const accessToken = await this.jwt.signAsync(payload, {
            expiresIn: '1h',
            secret: secret,
        });
        return {
            access_token: accessToken,
        };
    }

}