# install prisma

```
yarn add -D prisma
yarn add @prisma/client
npx prisma init
```

### migrate

```
npx prisma migrate dev
```

### studio(DB 確認)

```
npx prisma studio
```

### generate(型自動生成)

```
npx prisma generate
```

# add docker-compose.yml file

### start db

```
docker compose up -d
```

#### reset db

```
docker compose rm -s -f -v
```

# install packages

```
yarn add @nestjs/config @nestjs/jwt @nestjs/passport
yarn add cookie-parser csurf passport passport-jwt bcrypt class-validator
yarn add -D @types/express @types/cookie-parser @types/csurf @types/passport-jwt @types/bcrypt
yarn add class-transformer
```

# CLI

### endpoint

```
nest g  resource ***
```

### prisma

```
nest g module prisma
nest g service prisma --no-spec
```

# Project Setup

<details>
<summary>main.ts</summary>

```
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { Request } from 'express';
import * as cookieParser from 'cookie-parser';
import * as csurf from 'csurf';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  app.enableCors({
    credentials: true,
    origin: ['http://localhost:3000', '本番URL'],
  });
  app.use(cookieParser());
  app.use(
    csurf({
      cookie: {
        httpOnly: true,
        sameSite: 'none',
        secure: true,
      },
      value: (req: Request) => {
        return req.header('csrf-token');
      },
    }),
  );
  await app.listen(process.env.PORT || 3005);
}
bootstrap();

```

### cors おまじない

```
  app.enableCors({
    credentials: true,
    origin: ['http://localhost:3000', '本番URL'],
  });
```

</details>

# prisma setup

<details>
<summary>PrismaService.ts</summary>

```
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor(private readonly config: ConfigService) {
    super({
      datasources: {
        db: {
          url: config.get('DATABASE_URL'),
        },
      },
    });
  }
}

```

</details>

<details>
<summary>PrismaModule.ts</summary>

```
import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}

```

</details>

# Auth setup

<details>
<summary>AuthModule</summary>

Imports に JwtModule.register({})追加

```
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [PrismaModule, JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}

```

</details>

.env に追記

```
JWT_SECRET='HOGE'
```

### dto

class-validator から validator をかける

```
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class AuthDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(5)
  password: string;
}

```

### AuthService

まず DI

```
 constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}
```

signUp 関数作成

```
async signUp(dto: AuthDto): Promise<Msg> {
    const hashed = await bcrypt.hash(dto.password, 12); // 12回計算する
    try {
      await this.prisma.user.create({
        data: {
          email: dto.email, // dtoは受け取った値
          hashedPassword: hashed,
        },
      });
      return {
        message: 'ok',
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('This email is already taken');
        }
      }
      throw error;
    }
  }
```

login 関数作成

```
async login(dto: AuthDto): Promise<Jwt> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Email or password incorrect');
    const isValid = await bcrypt.compare(dto.password, user.hashedPassword); // hashedPasswordを解析
    if (!isValid) throw new ForbiddenException('Email or password incorrect');
    return this.generateJwt(user.id, user.email); // { accessToken: token };
  }
```

generateJwt 関数作成

```
async generateJwt(userId: number, email: string): Promise<Jwt> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '5m',
      secret: secret,
    });
    return { accessToken: token };
  }
```

### AuthController

```
export class AuthController {
  constructor(private readonly authService: AuthService) {} // DI

  @Post('/signup')
  signUp(@Body() dto: AuthDto): Promise<Msg> {
    return this.authService.signUp(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('/login')
  async login(
    @Body() dto: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<Msg> {
    const jwt = await this.authService.login(dto);
    res.cookie('access_token', jwt.accessToken, {
      httpOnly: true,
      secure: false, // httpsでは true
      sameSite: 'none',
      path: '/',
    });
    return {
      message: 'ok',
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/logout')
  logout(@Req() _req: Request, @Res({ passthrough: true }) res: Response): Msg {
    res.cookie('access_token', '', {
      httpOnly: true,
      secure: false, // httpsでは true
      sameSite: 'none',
      path: '/',
    });
    return {
      message: 'ok',
    };
  }
}

```

### Strategy

```
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => {
          let jwt = null;
          if (req && req.cookies) {
            jwt = req.cookies['access_token'];
          }
          return jwt;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: config.get('JWT_SECRET'),
    });
  }

  async validate(payload: { sub: number; email: string }) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: payload.sub,
      },
    });
    delete user.hashedPassword;
    return user;
  }
}

```

# User setup

コードが読める規模なので書かない

# Todo setup
