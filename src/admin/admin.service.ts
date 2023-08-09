import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateAdminDto } from './dto/create-admin.dto';
import { UpdateAdminDto } from './dto/update-admin.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Admin, AdminDocument } from './schemas/admin.schrema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AdminService {
  constructor(
    @InjectModel(Admin.name) private adminModel: Model<Admin>,
    private readonly jwtService: JwtService,
  ) {}

  async create(createAdminDto: CreateAdminDto) {
    const { password, confirm_password } = createAdminDto;
    if (password !== confirm_password) {
      return new BadRequestException('password is not match');
    }
    const hashed_password = await bcrypt.hash(password, 7);

    const createdAdmin = await this.adminModel.create({
      ...createAdminDto,
      hashed_password,
    });

    const tokens = await this.generateToken(createdAdmin);
    console.log(tokens);

    const hashed_token = await bcrypt.hash(tokens.refresh_token, 7);
    const updatedAdmin = await this.adminModel.findByIdAndUpdate(
      createdAdmin.id,
      { hashed_token },
      { new: true },
    );
    return updatedAdmin;
  }

  async findAll(): Promise<Admin[]> {
    const admins = await this.adminModel.find();
    return admins;
  }

  async findOne(id: string) {
    const admin = await this.adminModel.findById(id).exec();
    if (!admin) {
      throw new HttpException('Admin topilmadi', HttpStatus.NOT_FOUND);
    }
    return admin;
  }

  async updateAdmin(
    id: string,
    updateAdminDto: UpdateAdminDto,
  ): Promise<Admin> {
    const admin = await this.adminModel
      .findByIdAndUpdate(id, updateAdminDto, {
        new: true,
      })
      .exec();
    if (!admin) {
      throw new NotFoundException('Admin topilmadi');
    }
    return admin;
  }

  remove(id: string) {
    return this.adminModel.findByIdAndDelete(id);
  }

  async generateToken(admin: AdminDocument) {
    const jwtPayload = {
      id: admin._id,
      is_creator: admin.is_creator,
      is_active: admin.is_active,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.sign(jwtPayload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    const response = {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
    return response;
  }
}
