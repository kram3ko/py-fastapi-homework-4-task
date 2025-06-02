from fastapi import APIRouter, HTTPException
from fastapi.params import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette import status
from database import get_db, UserModel, UserGroupEnum, UserProfileModel

from config import get_jwt_auth_manager, get_s3_storage_client
from database.models.accounts import GenderEnum
from exceptions import BaseSecurityError, S3FileUploadError
from schemas.profiles import ProfileResponseSchema, ProfileCreateRequestSchema
from security.http import get_token
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface

router = APIRouter()


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    summary="Create a new profile for a user",
    status_code=status.HTTP_201_CREATED
)
async def create_profile(
    user_id: int,
    profile_data: ProfileCreateRequestSchema = Depends(
        ProfileCreateRequestSchema.as_form
    ),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(get_token),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    s3_client: S3StorageInterface = Depends(get_s3_storage_client),
):
    """
    create a new profile for a user.

     Args:
        user_id (int): The ID of the user for whom the profile is being created.
        profile_data (ProfileCreateRequestSchema): The profile data to be created.
        token (str): The authentication token.
        jwt_manager (JWTAuthManagerInterface): JWT manager for decoding tokens.
        db (AsyncSession): The asynchronous database session.
        s3_client (S3StorageInterface): The asynchronous S3 storage client.

    Returns:
        ProfileResponseSchema: The created user profile details.
    """
    try:
        payload = jwt_manager.decode_access_token(token)
        token_user_id = payload.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

    stmt_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = stmt_user.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    if user_id != token_user_id:
        result = await db.execute(
            select(UserModel).options(selectinload(UserModel.group)).where(UserModel.id == token_user_id)
        )
        admin_user = result.scalars().first()
        if not admin_user or admin_user.group.name != UserGroupEnum.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to edit this profile."
            )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active."
        )

    stmt_profile = await db.execute(
        select(UserProfileModel).where(UserProfileModel.user_id == user_id))
    result_profile = stmt_profile.scalars().first()
    if result_profile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile."
        )

    avatar_bytes = await profile_data.avatar.read()
    avatar_key = f"avatars/{user.id}_{profile_data.avatar.filename}"
    try:
        await s3_client.upload_file(file_name=avatar_key, file_data=avatar_bytes)
    except S3FileUploadError as e:
        print(f"Error uploading avatar: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later."
        )

    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=profile_data.first_name,
        last_name=profile_data.last_name,
        gender=GenderEnum(profile_data.gender),
        date_of_birth=profile_data.date_of_birth,
        info=profile_data.info,
        avatar=avatar_key
    )

    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)
    avatar_url = await s3_client.get_file_url(new_profile.avatar)

    return ProfileResponseSchema(
        id=new_profile.id,
        user_id=new_profile.user_id,
        first_name=new_profile.first_name,
        last_name=new_profile.last_name,
        gender=new_profile.gender,
        date_of_birth=new_profile.date_of_birth,
        info=new_profile.info,
        avatar=avatar_url
    )
