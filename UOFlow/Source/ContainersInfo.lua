
ContainersInfo = {}

ContainersInfo.DefaultGump = 60 -- backpack
ContainersInfo.DefaultCorpse = 9 -- coffin

ContainersInfo.Data = {
-- [1.. N] = {name = "", ItemsId = {}, GumpId = 0, Texture = "" }
-- Texture can be null, but if specified will override the gumpId.

	[1]	 = {name = "bucket", ItemsId = {5344}, GumpId = 62}, -- original gump id: 9
	[2]	 = {name = "cauldron", ItemsId = {8296}, GumpId = 9},
	[3]	 = {name = "sacrificial altar", ItemsId = {10906, 10907, 10908, 10909}, GumpId = 9},
	[4]	 = {name = "corpse", ItemsId = {8198}, GumpId = 9},
	[5]	 = {name = "bones", ItemsId = {3786, 3787, 3788, 3789, 3790,  3791, 3792, 3793, 3794 }, GumpId = 9},
	[6]	 = {name = "backpack", ItemsId = {2482, 3701, 42783, 42784,	42785, 42786}, GumpId = 60},
	[7]	 = {name = "belt pouch", ItemsId = {3705}, GumpId = 60},
	[8]	 = {name = "bag", ItemsId = {3702, 42211, 42212}, GumpId = 61},
	[9]	 = {name = "bagball", ItemsId = {8790, 8791}, GumpId = 61},
	[10] = {name = "barrel", ItemsId = {3703}, GumpId = 62},
	[11] = {name = "closed barrel", ItemsId = {4014}, GumpId = 62},
	[12] = {name = "keg", ItemsId = {3711}, GumpId = 62},
	[13] = {name = "short barrel", ItemsId = {3715}, GumpId = 62},
	[14] = {name = "piknik basket", ItemsId = {3706}, GumpId = 63},
	[15] = {name = "piknik basket with handle", ItemsId = {9433, 9434}, GumpId = 63},
	[16] = {name = "short rect basket", ItemsId = {9429, 9430}, GumpId = 63},
	[17] = {name = "incubator", ItemsId = {16508, 16509}, GumpId = 64},
	[18] = {name = "round basket", ItemsId = {2448}, GumpId = 65},
	[19] = {name = "basket", ItemsId = {9437, 42924, 42925, 42926}, GumpId = 65},
	[20] = {name = "tall round basket", ItemsId = {9432}, GumpId = 65},
	[21] = {name = "small round basket", ItemsId = {9431}, GumpId = 65},
	[22] = {name = "round basket with handle", ItemsId = {2476}, GumpId = 65},
	[23] = {name = "flat round basket ", ItemsId = {2481}, GumpId = 65},
	[24] = {name = "golden metal chest", ItemsId = {3648, 3649, 43089, 43090}, GumpId = 66},
	[25] = {name = "gargish chest", ItemsId = {16421, 16422}, GumpId = 66},
	[26] = {name = "wooden box", ItemsId = {3709, 2474}, GumpId = 67},
	[27] = {name = "small crate", ItemsId = {2473, 3710, 42312, 42313, 44121, 44138}, GumpId = 68},
	[28] = {name = "large crate", ItemsId = {3644, 3645, 42343, 42344, 42345, 42346}, GumpId = 68},
	[29] = {name = "medium crate", ItemsId = {3646, 3647}, GumpId = 68},
	[30] = {name = "chest of drawers (red)", ItemsId = {2608, 2616, 42286, 42287}, GumpId = 72},
	[31] = {name = "wooden chest", ItemsId = {3650, 3651, 42553, 42554, 42555, 42556, 43087, 43088}, GumpId = 73},
	[32] = {name = "metal chest", ItemsId = {2475, 3708}, GumpId = 74},
	[33] = {name = "strongbox", ItemsId = {3712, 2472}, GumpId = 75},
	[34] = {name = "ship cargo", ItemsId = {15973, 16019, 16046, 16057}, GumpId = 76},
	[35] = {name = "cargo hold", ItemsId = {37374}, GumpId = 76},
	[36] = {name = "wooden shelf", ItemsId = {2717, 2718}, GumpId = 77},
	[37] = {name = "wooden bookcase", ItemsId = {2711, 2712, 2713, 2714, 2715, 2716, 42472, 42473}, GumpId = 77},
	[38] = {name = "armoire", ItemsId = {2636, 2637, 2640, 2641}, GumpId = 78},
	[39] = {name = "armoire", ItemsId = {2638, 2639, 2642, 2643}, GumpId = 79},
	[40] = {name = "chest of drawers (plain)", ItemsId = {2604, 2612}, GumpId = 81},
	[41] = {name = "gift box", ItemsId = {9002, 9003}, GumpId = 258},
	[42] = {name = "stocking", ItemsId = {11225, 11226, 11227, 11228}, GumpId = 259},
	[43] = {name = "maple armoire", ItemsId = {10331, 10332}, GumpId = 260},
	[44] = {name = "elven wash basin", ItemsId = {12511, 12512, 12513, 12514}, GumpId = 260},
	[45] = {name = "elegant armoire", ItemsId = {10329, 10330}, GumpId = 262},
	[46] = {name = "elven dresser", ItemsId = {12515, 12516, 12517, 12518}, GumpId = 262},
	[47] = {name = "red armoire", ItemsId = {10327, 10328}, GumpId = 263},
	[48] = {name = "cherry armoire", ItemsId = {10333, 10334}, GumpId = 263},
	[49] = {name = "arcane bookshelf", ItemsId = {12420, 12421, 12422, 12423}, GumpId = 263},
	[50] = {name = "tall square basket ", ItemsId = {9435, 9436}, GumpId = 264},
	[51] = {name = "plain wooden chest", ItemsId = {10251, 10252}, GumpId = 265},
	[52] = {name = "ornate wooden chest", ItemsId = {10253, 10254}, GumpId = 265},
	[53] = {name = "gilded chest", ItemsId = {10255, 10256, 43081, 43082}, GumpId = 266},
	[54] = {name = "wooden footlocker", ItemsId = {10257, 10258}, GumpId = 267},
	[55] = {name = "finished wooden chest", ItemsId = {10259, 10260}, GumpId = 267},
	[56] = {name = "rarewood chest", ItemsId = {11761, 11762}, GumpId = 268},
	[57] = {name = "decorative box", ItemsId = {11763, 11764}, GumpId = 268},
	[58] = {name = "tall cabinet", ItemsId = {10261, 10262}, GumpId = 268},
	[59] = {name = "short cabinet", ItemsId = {10263, 10264}, GumpId = 268},
	[60] = {name = "fancy elven armoire", ItemsId = {11528, 11527}, GumpId = 268},
	[61] = {name = "simple elven armoire", ItemsId = {11525, 11526}, GumpId = 268},
	[62] = {name = "ronate elven chest", ItemsId = {12440, 12441, 12442, 12443}, GumpId = 268},
	[63] = {name = "ter-mur style dresser", ItemsId = {16427, 16428, 16429, 16430}, GumpId = 269},
	[64] = {name = "blessed statue", ItemsId = {6473, 6474}, GumpId = 278},
	[65] = {name = "mailbox", ItemsId = {16705, 16706, 16707, 16708}, GumpId = 282},
	[66] = {name = "square xmas box", ItemsId = {18082}, GumpId = 283},
	[67] = {name = "round xmas box", ItemsId = {18083}, GumpId = 284},
	[68] = {name = "hex xmas box", ItemsId = {18084}, GumpId = 285},
	[69] = {name = "rect xmas box", ItemsId = {18086, 18085}, GumpId = 286},
	[70] = {name = "angel box", ItemsId = {18087}, GumpId = 287},
	[71] = {name = "heart shaped box", ItemsId = {18890, 18891, 18892, 18893, 18894, 18895, 18896, 18897, 18898, 18899}, GumpId = 288},
	[72] = {name = "tall gift box", ItemsId = {18888, 18889}, GumpId = 289},
	[73] = {name = "fountain of life", ItemsId = {10944, 10945, 10946, 10947, 10948, 10949}, GumpId = 1156},
	[74] = {name = "secret chest", ItemsId = {38662}, GumpId = 1422},
	[75] = {name = "checker board", ItemsId = {4006}, GumpId = 2330},
	[76] = {name = "backgammon", ItemsId = {3612, 4013}, GumpId = 2350},
	[77] = {name = "king's collection box", ItemsId = {19724, 19725}, GumpId = 19724},
	[78] = {name = "wedding chest", ItemsId = {40852, 40853}, GumpId = 9834},
	[79] = {name = "obelisk base", ItemsId = {40866}, GumpId = 9835},
	[80] = {name = "wooden chest", ItemsId = {40952, 40953}, GumpId = 40153},
	[81] = {name = "ore satchel", ItemsId = {41586, 41587}, GumpId = 40164},
	[82] = {name = "wood satchel", ItemsId = {41588, 41589}, GumpId = 40165},
	[83] = {name = "dolphin mailbox", ItemsId = {41476, 41477, 41474, 41475}, GumpId = 1747},
	[84] = {name = "squirel mailbox", ItemsId = {41478, 41479, 41480, 41481}, GumpId = 1748},
	[85] = {name = "barrel mailbox", ItemsId = {41461, 41463, 41464, 41465}, GumpId = 1749},
	[86] = {name = "lighthouse mailbox", ItemsId = {41577, 41579, 41576, 41581, 41583, 41580}, GumpId = 1750},
	[87] = {name = "cannon", ItemsId = {16918, 16919, 16920, 16921, 16922, 16923, 16924, 16925, 41664, 41665, 41666, 41667, 41979, 41980, 41981, 41982}, GumpId = 40167},
	[89] = {name = "sitting kitten mailbox", ItemsId = {41963, 41964, 41965, 41966}, GumpId = 40247},
	[90] = {name = "standing kitten mailbox", ItemsId = {41967, 41968, 41969, 41970}, GumpId = 40248},
	[91] = {name = "scarecrow mailbox", ItemsId = {41971, 41972, 41973, 41974}, GumpId = 40249},
	[92] = {name = "lion mailbox", ItemsId = {41975, 41976, 41978, 41979}, GumpId = 40250},
	[93] = {name = "2020 fountains", ItemsId = {42541, 42544, 42547, 42550, 42538}, GumpId = 40276},

}

-- Content label location on legacy containers
ContainersInfo.LegacyContentLabelLocation = {
	[9] = {x=-40, y=10},
	[60] = {x=0, y=-20},
	[61] = {x=-10, y=10},
	[62] = {x=-20, y=10},
	[63] = {x=0, y=-40},
	[64] = {x=0, y=-10},
	[65] = {x=0, y=10},
	[66] = {x=-40, y=10},
	[67] = {x=0, y=-50},
	[68] = {x=0, y=-60},
	[72] = {x=0, y=-30},
	[73] = {x=-40, y=10},
	[74] = {x=-40, y=10},
	[75] = {x=0, y=-40},
	[76] = {x=0, y=-60},
	[77] = {x=0, y=-90},
	[78] = {x=-40, y=0},
	[79] = {x=-40, y=0},
	[81] = {x=5, y=-30},
	[258] = {x=0, y=-90},
	[259] = {x=10, y=-10},
	[260] = {x=5, y=-30},
	[261] = {x=5, y=-30},
	[262] = {x=5, y=-30},
	[263] = {x=5, y=-30},
	[264] = {x=10, y=-30},
	[265] = {x=5, y=-30},
	[266] = {x=5, y=-30},
	[267] = {x=5, y=-30},
	[268] = {x=5, y=-30},
	[269] = {x=5, y=-30},
	[270] = {x=5, y=-30},
	[278] = {x=10, y=-50},
	[282] = {x=-60, y=0},
	[283] = {x=5, y=-70},
	[284] = {x=0, y=0},
	[285] = {x=0, y=-30},
	[286] = {x=20, y=-150},
	[287] = {x=5, y=-60},
	[288] = {x=10, y=-80},
	[289] = {x=10, y=-110},
	[1156] = {x=0, y=-10},
	[1422] = {x=10, y=-110},
	[2330] = {x=0, y=-60},
	[2350] = {x=0, y=-90},
	[19724] = {x=5, y=-60},
	[9834] = {x=0, y=-40},
	[9835] = {x=0, y=-40},
}


function ContainersInfo.GetGump(id,defaultGump)
	if not WindowData.ObjectInfo[id] then
		RegisterWindowData(WindowData.ObjectInfo.Type, id)
	end

	if (id == ContainerWindow.PlayerBackpack) then
		if(SystemData.Settings.GameOptions.myLegacyBackpackType == SystemData.Settings.LegacyBackpackStyle.LEGACY_BACKPACK_SUEDE)then			
			return ContainerWindow.SUEDE_BACKPACK			
		end

		if(SystemData.Settings.GameOptions.myLegacyBackpackType == SystemData.Settings.LegacyBackpackStyle.LEGACY_BACKPACK_POLAR_BEAR)then			
			return ContainerWindow.POLAR_BEAR_BACKPACK			
		end

		if(SystemData.Settings.GameOptions.myLegacyBackpackType == SystemData.Settings.LegacyBackpackStyle.LEGACY_BACKPACK_GHOUL_SKIN)then			
			return ContainerWindow.GHOUL_SKIN_BACKPACK			
		end
	end

	--Debug.Print(WindowData.ObjectInfo[id].objectType)
	--Debug.Print(WindowData.ContainerWindow[id].gumpNum )
	--Debug.Print("----------")
	if WindowData.ContainerWindow[id].isCorpse then
		return ContainersInfo.DefaultCorpse, "corpse" -- coffin gump
	end
	if WindowData.ObjectInfo[id] then
		for i = 1, #ContainersInfo.Data do
			local val = ContainersInfo.Data[i]
			for k = 1, #val.ItemsId do
				if val.ItemsId[k] == WindowData.ObjectInfo[id].objectType then
					return val.GumpId, val.name, val.Texture
				end
			end
		end
	end
	return defaultGump 
end