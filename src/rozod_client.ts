import { fetchApi } from "rozod";

import {
  postUsernamesUsers,
  getUsersUserid
} from "rozod/lib/endpoints/usersv1";

import {
  getUsersAvatar,
  getGamesIcons,
  getGroupsIcons,
  getGamesMultigetThumbnails
} from "rozod/lib/endpoints/thumbnailsv1";

import { getGroupsGroupid } from "rozod/lib/endpoints/groupsv1";

export async function get_user_id_from_name(username: string): Promise<string | number> {
  const response = await fetchApi(postUsernamesUsers,
    {
      body: {
        usernames: [username],
        excludeBannedUsers: false
      }
    },
    { returnRaw: true }
  );

  return (await response.json()).data[0]?.id ?? "No user found";
}

export async function get_user_info_from_id(user_id: string) {
  const response = await fetchApi(getUsersUserid, {
    userId: Number(user_id)
  }, { returnRaw: true });

  return (await response.json()) ?? "No user found";
}

export async function get_user_avatar_icon(user_id: string) {
  const response = await fetchApi(getUsersAvatar, {
    userIds: [Number(user_id)],
    format: "Png",
    isCircular: false
  }, { returnRaw: true });

  return (await response.json()).data[0]?.imageUrl ?? "No avatar found";
}

export async function get_game_icon(game_id: string) {
  const response = await fetchApi(getGamesIcons, {
    universeIds: [Number(game_id)],
    format: "Png",
    isCircular: false,
    size: "512x512"
  }, { returnRaw: true });

  return (await response.json()).data[0]?.imageUrl ?? "No icon found";
}

export async function get_group_icon(group_id: string) {
  const response = await fetchApi(getGroupsIcons, {
    groupIds: [Number(group_id)],
    format: "Png",
    isCircular: false,
    size: "420x420"
  }, { returnRaw: true });

  return (await response.json()).data[0]?.imageUrl ?? "No icon found";
}

export async function get_first_game_thumbnail_from_game_id(game_id: string) {
  const response = await fetchApi(getGamesMultigetThumbnails, {
    universeIds: [Number(game_id)],
    format: "Png",
    isCircular: false,
    size: "768x432"
  }, { returnRaw: true });

  return (await response.json()).data[0]?.thumbnails[0]?.imageUrl ?? "No thumbnail found";
}

export async function get_group_info_from_id(group_id: string) {
  const response = await fetchApi(getGroupsGroupid, {
    groupId: Number(group_id)
  }, { returnRaw: true });

  return (await response.json()) ?? "No group found";
}
