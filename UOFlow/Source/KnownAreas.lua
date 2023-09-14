----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------
KnownAreas = {}
-------------------------------------------------------------------
KnownAreas["Unique Areas"] = {}
KnownAreas["Unique Areas"].MainAreas ={
		{x1 = 984, y1 = 540, x2 = 998, y2 = 553, map = 0, name="Serpent Cross Tavern", shard=0};
		
}
KnownAreas["Unique Areas"].Guarded = false
KnownAreas["Unique Areas"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Guarded Moongates"] = {}
KnownAreas["Guarded Moongates"].MainAreas ={
		-- FELUCCA
		{x1 = 1336, y1 = 1991, x2 = 1342, y2 = 2003, map = 0, name="Britain Moongate"};
		{x1 = 1494, y1 = 3767, x2 = 1506, y2 = 3778, map = 0, name="Jhelom Moongate"};
		{x1 = 2694, y1 = 685, x2 = 1506, y2 = 701, map = 0, name="Minoc Moongate"};
		{x1 = 1823, y1 = 2943, x2 = 1834, y2 = 2954, map = 0, name="Trinsic Moongate"};
		{x1 = 761, y1 = 741, x2 = 780, y2 = 762, map = 0, name="Yew Moongate"};
		{x1 = 638, y1 = 2062, x2 = 650, y2 = 2073, map = 0, name="Skara Brae Moongate"};
		{x1 = 4459, y1 = 1276, x2 = 4475, y2 = 1292, map = 0, name="Moonglow Moongate"};
		{x1 = 3554, y1 = 2132, x2 = 3572, y2 = 2150, map = 0, name="Magincia Moongate"};
		-- TRAMMEL
		{x1 = 1330, y1 = 1991, x2 = 1342, y2 = 2003, map = 1, name="Britain Moongate"};
		{x1 = 1494, y1 = 3767, x2 = 1506, y2 = 3778, map = 1, name="Jhelom Moongate"};
		{x1 = 2694, y1 = 685, x2 = 1506, y2 = 701, map = 1, name="Minoc Moongate"};
		{x1 = 1823, y1 = 2943, x2 = 1834, y2 = 2954, map = 1, name="Trinsic Moongate"};
		{x1 = 761, y1 = 741, x2 = 780, y2 = 762, map = 1, name="Yew Moongate"};
		{x1 = 638, y1 = 2062, x2 = 650, y2 = 2073, map = 1, name="Skara Brae Moongate"};
		{x1 = 4459, y1 = 1276, x2 = 4475, y2 = 1292, map = 1, name="Moonglow Moongate"};
		{x1 = 3554, y1 = 2132, x2 = 3572, y2 = 2150, map = 1, name="Magincia Moongate"};
		{x1 = 3447, y1 = 2673, x2 = 3456, y2 = 2682, map = 1, name="New Haven Moongate"};
}
KnownAreas["Guarded Moongates"].Guarded = true
KnownAreas["Guarded Moongates"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Shrine"] = {}
KnownAreas["Shrine"].MainAreas ={
		{x1 = 512, y1 = 200, x2 = 544, y2 = 232, map = 2, name="Shrine of Valor"};
		{x1 = 1736, y1 = 224, x2 = 1760, y2 = 248, map = 2, name="Shrine of Chaos"};
		{x1 = 1160, y1 = 1280, x2 = 1192, y2 = 1296, map = 2, name="Shrine of Sacrifice"};
		{x1 = 712, y1 = 1344, x2 = 736, y2 = 1376, map = 2, name="Shrine of Honesty"};
		{x1 = 1200, y1 = 448, x2 = 1232, y2 = 488, map = 2, name="Shrine of Compassion"};
		{x1 = 1520, y1 = 1336, x2 = 1536, y2 = 1352, map = 2, name="Shrine of Spirituality"};
		{x1 = 272, y1 = 1008, x2 = 296, y2 = 1024, map = 2, name="Shrine of Humility"};
		{x1 = 736, y1 = 712, x2 = 760, y2 = 744, map = 2, name="Shrine of Honor"};
		{x1 = 982, y1 = 994, x2 = 989, y2 = 1004, map = 2, name="Shrine of Justice"};
}
KnownAreas["Shrine"].Guarded = true
KnownAreas["Shrine"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Twisted Weald"] = {}
KnownAreas["Twisted Weald"].MainAreas ={
			{x1 = 2107, y1 = 1145, x2 = 2254, y2 = 1280, map = 2};
}
KnownAreas["Twisted Weald"].Guarded = false
KnownAreas["Twisted Weald"].SubAreas = {}
	KnownAreas["Twisted Weald"].SubAreas["Twisted Glade Champion Spawn"] = {}
	KnownAreas["Twisted Weald"].SubAreas["Twisted Glade Champion Spawn"].Prior = true
	KnownAreas["Twisted Weald"].SubAreas["Twisted Glade Champion Spawn"].Squares = {
			{x1 = 2210, y1 = 1260, squareCenter = 24, map = 2};
	}
	KnownAreas["Twisted Weald"].SubAreas["Twisted Weald - Quicksand"] = {}
	KnownAreas["Twisted Weald"].SubAreas["Twisted Weald - Quicksand"].Squares = {
			{x1 = 2139, y1 = 1187, x2 = 2152, y2 = 1193, map = 2};
			{x1 = 2152, y1 = 1160, x2 = 2230, y2 = 1196, map = 2};
			{x1 = 2190, y1 = 1186, x2 = 2224, y2 = 1210, map = 2};
	}
	
-------------------------------------------------------------------
KnownAreas["Mushroom Cave"] = {}
KnownAreas["Mushroom Cave"].MainAreas ={
			{x1 = 1392, y1 = 1448, x2 = 1496, y2 = 1568, map = 2};
}
KnownAreas["Mushroom Cave"].Guarded = false
KnownAreas["Mushroom Cave"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Heartwood"] = {}
KnownAreas["Heartwood"].MainAreas ={
			{x1 = 6911, y1 = 255, x2 = 7168, y2 = 515, map = 0};
			{x1 = 6911, y1 = 255, x2 = 7168, y2 = 515, map = 1};
}
KnownAreas["Heartwood"].Guarded = true
KnownAreas["Heartwood"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Painted Caves"] = {}
KnownAreas["Painted Caves"].MainAreas ={
			{x1 = 6240, y1 = 860, x2 = 6310, y2 = 920, map = 0};
			{x1 = 6240, y1 = 860, x2 = 6310, y2 = 920, map = 1};
}
KnownAreas["Painted Caves"].Guarded = false
KnownAreas["Painted Caves"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Prism of Light"] = {}
KnownAreas["Prism of Light"].MainAreas ={
			{x1 = 6400, y1 = 0, x2 = 6621, y2 = 255, map = 0};
			{x1 = 6400, y1 = 0, x2 = 6621, y2 = 255, map = 1};
}
KnownAreas["Prism of Light"].Guarded = false
KnownAreas["Prism of Light"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Blighted Grove"] = {}
KnownAreas["Blighted Grove"].MainAreas ={
			{x1 = 6440, y1 = 820, x2 = 6600, y2 = 970, map = 0};
			{x1 = 6440, y1 = 820, x2 = 6600, y2 = 970, map = 1};
}
KnownAreas["Blighted Grove"].Guarded = false
KnownAreas["Blighted Grove"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Palace of Paroxysmus"] = {}
KnownAreas["Palace of Paroxysmus"].MainAreas ={
			{x1 = 6191, y1 = 311, x2 = 6561, y2 = 671, map = 0};
			{x1 = 6191, y1 = 311, x2 = 6561, y2 = 671, map = 1};
}
KnownAreas["Palace of Paroxysmus"].Guarded = false
KnownAreas["Palace of Paroxysmus"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Orc Cave"] = {}
KnownAreas["Orc Cave"].MainAreas ={
			{x1 = 5281, y1 = 1283, x2 = 5373, y2 = 1386, map = 0};
			{x1 = 5267, y1 = 1955, x2 = 5364, y2 = 2046, map = 0};
			{x1 = 5127, y1 = 1941, x2 = 5164, y2 = 2024, map = 0};
			{x1 = 5281, y1 = 1283, x2 = 5373, y2 = 1386, map = 1};
			{x1 = 5267, y1 = 1955, x2 = 5364, y2 = 2046, map = 1};
			{x1 = 5127, y1 = 1941, x2 = 5164, y2 = 2024, map = 1};
}
KnownAreas["Orc Cave"].Guarded = false
KnownAreas["Orc Cave"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Sanctuary"] = {}
KnownAreas["Sanctuary"].MainAreas ={
			{x1 = 6144, y1 = 0, x2 = 6399, y2 = 255, map = 0};
			{x1 = 6144, y1 = 0, x2 = 6399, y2 = 255, map = 1};
}
KnownAreas["Sanctuary"].Guarded = false
KnownAreas["Sanctuary"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Covetous"] = {}
KnownAreas["Covetous"].MainAreas ={
			{x1 = 5376, y1 = 1793, x2 = 5577, y2 = 2048, map = 0};
			{x1 = 5576, y1 = 1791, x2 = 5633, y2 = 2048, map = 0};
			{x1 = 5376, y1 = 1793, x2 = 5577, y2 = 2048, map = 1};
			{x1 = 5576, y1 = 1791, x2 = 5633, y2 = 2048, map = 1};
}
KnownAreas["Covetous"].SubAreas = {}
	KnownAreas["Covetous"].SubAreas["The Void Pool"] = {}
	KnownAreas["Covetous"].SubAreas["The Void Pool"].Prior = true
	KnownAreas["Covetous"].SubAreas["The Void Pool"].Squares = {
			{x1 = 5378, y1 = 1962, x2 = 5630, y2 = 2043, map = 0};
			{x1 = 5378, y1 = 1962, x2 = 5630, y2 = 2043, map = 1};
			{x1 = 5429, y1 = 1944, x2 = 5492, y2 = 1968, map = 0};
			{x1 = 5429, y1 = 1944, x2 = 5492, y2 = 1968, map = 1};
	}
	KnownAreas["Covetous"].SubAreas["The Void Pool"].LocalStats = {
		barddiff=L"?";
		physical=L"? - ?";
		fire=L"? - ?";
		cold=L"? - ?";
		poison=L"? - ?";
		energy=L"? - ?";
	}
	
	KnownAreas["Covetous"].SubAreas["Covetous Level 3"] = {}
	KnownAreas["Covetous"].SubAreas["Covetous Level 3"].Prior = true
	KnownAreas["Covetous"].SubAreas["Covetous Level 3"].Squares = {
			{x1 = 5530, y1 = 1820, x2 = 5627, y2 = 1930, map = 0};
			{x1 = 5530, y1 = 1820, x2 = 5627, y2 = 1930, map = 1};
	}
	KnownAreas["Covetous"].SubAreas["Covetous Level 3"].LocalStats = {
		barddiff=L"110 - 160";
		physical=L"70 - 95";
		fire=L"70 - 95";
		cold=L"70 - 95";
		poison=L"70 - 95";
		energy=L"70 - 95";
	}
	
	KnownAreas["Covetous"].SubAreas["Covetous Prison"] = {}
	KnownAreas["Covetous"].SubAreas["Covetous Prison"].Prior = true
	KnownAreas["Covetous"].SubAreas["Covetous Prison"].Squares = {
			{x1 = 5500, y1 = 1795, x2 = 5565, y2 = 1820, map = 0};
			{x1 = 5500, y1 = 1795, x2 = 5565, y2 = 1820, map = 1};
	}
	KnownAreas["Covetous"].SubAreas["Covetous Prison"].LocalStats = {
		barddiff=L"160";
		physical=L"90 - 100";
		fire=L"90 - 100";
		cold=L"90 - 100";
		poison=L"90 - 100";
		energy=L"90 - 100";
	}
KnownAreas["Covetous"].Guarded = false
-------------------------------------------------------------------
KnownAreas["Deceit"] = {}
KnownAreas["Deceit"].MainAreas ={
			{x1 = 5122, y1 = 518, x2 = 5370, y2 = 770, map = 0};
			{x1 = 5122, y1 = 518, x2 = 5370, y2 = 770, map = 1};
}
KnownAreas["Deceit"].Guarded = false
KnownAreas["Deceit"].SubAreas = {}
	KnownAreas["Deceit"].SubAreas["Unholy Terror Champion Spawn"] = {}
	KnownAreas["Deceit"].SubAreas["Unholy Terror Champion Spawn"].Prior = true
	KnownAreas["Deceit"].SubAreas["Unholy Terror Champion Spawn"].Squares = {
			{x1 = 5178, y1 = 708, squareCenter = 49, map = 0};
	}
-------------------------------------------------------------------
KnownAreas["Despise"] = {}
KnownAreas["Despise"].MainAreas ={
			{x1 = 5377, y1 = 516, x2 = 5631, y2 = 1022, map = 0};
			{x1 = 5377, y1 = 516, x2 = 5631, y2 = 1022, map = 1};
}
KnownAreas["Despise"].Guarded = false
KnownAreas["Despise"].SubAreas = {}
	KnownAreas["Despise"].SubAreas["Vermin Horde Champion Spawn"] = {}
	KnownAreas["Despise"].SubAreas["Vermin Horde Champion Spawn"].Prior = true
	KnownAreas["Despise"].SubAreas["Vermin Horde Champion Spawn"].Squares = {
			{x1 = 5557, y1 = 826, squareCenter = 49, map = 0};
	}
-------------------------------------------------------------------
KnownAreas["Destard"] = {}
KnownAreas["Destard"].MainAreas ={
			{x1 = 5120, y1 = 770, x2 = 5371, y2 = 1028, map = 0};
			{x1 = 5120, y1 = 770, x2 = 5371, y2 = 1028, map = 1};
}
KnownAreas["Destard"].Guarded = false
KnownAreas["Destard"].SubAreas = {}
	KnownAreas["Destard"].SubAreas["Cold Blood Champion Spawn"] = {}
	KnownAreas["Destard"].SubAreas["Cold Blood Champion Spawn"].Prior = true
	KnownAreas["Destard"].SubAreas["Cold Blood Champion Spawn"].Squares = {
			{x1 = 5259, y1 = 837, squareCenter = 49, map = 0};
	}
-------------------------------------------------------------------
KnownAreas["Hythloth"] = {}
KnownAreas["Hythloth"].MainAreas ={
			{x1 = 5898, y1 = 2, x2 = 6136, y2 = 246, map = 0};
			{x1 = 5898, y1 = 2, x2 = 6136, y2 = 246, map = 1};
}
KnownAreas["Hythloth"].Guarded = false
KnownAreas["Hythloth"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Khaldun"] = {}
KnownAreas["Khaldun"].MainAreas ={
			{x1 = 5381, y1 = 1284, x2 = 5628, y2 = 1539, map = 0};
			{x1 = 5381, y1 = 1284, x2 = 5628, y2 = 1539, map = 1};
}
KnownAreas["Khaldun"].Guarded = false
KnownAreas["Khaldun"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Shame"] = {}
KnownAreas["Shame"].MainAreas ={
			{x1 = 5377, y1 = 2, x2 = 5634, y2 = 262, map = 0};
			{x1 = 5635, y1 = 2, x2 = 5895, y2 = 126, map = 0};
			{x1 = 5377, y1 = 2, x2 = 5634, y2 = 262, map = 1};
			{x1 = 5635, y1 = 2, x2 = 5895, y2 = 126, map = 1};
}
KnownAreas["Shame"].Guarded = false
KnownAreas["Shame"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Wrong"] = {}
KnownAreas["Wrong"].MainAreas ={
			{x1 = 5633, y1 = 511, x2 = 5886, y2 = 1021, map = 0};
			{x1 = 5633, y1 = 511, x2 = 5886, y2 = 1021, map = 1};
}
KnownAreas["Wrong"].Guarded = false
KnownAreas["Wrong"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Terathan Keep"] = {}
KnownAreas["Terathan Keep"].MainAreas ={
			{x1 = 5404, y1 = 3099, x2 = 5121, y2 = 3167, map = 0};
			{x1 = 5120, y1 = 1530, x2 = 5374, y2 = 1788, map = 0};
			{x1 = 5404, y1 = 3099, x2 = 5121, y2 = 3167, map = 1};
			{x1 = 5120, y1 = 1530, x2 = 5374, y2 = 1788, map = 1};
}
KnownAreas["Terathan Keep"].Guarded = false
KnownAreas["Terathan Keep"].SubAreas = {}
	KnownAreas["Terathan Keep"].SubAreas["Arachnid Champion Spawn"] = {}
	KnownAreas["Terathan Keep"].SubAreas["Arachnid Champion Spawn"].Prior = true
	KnownAreas["Terathan Keep"].SubAreas["Arachnid Champion Spawn"].Squares = {
			{x1 = 5189, y1 = 1605, squareCenter = 49, map = 0};
	}
-------------------------------------------------------------------
KnownAreas["Fire"] = {}
KnownAreas["Fire"].MainAreas ={
			{x1 = 5635, y1 = 1285, x2 = 5880, y2 = 1520, map = 0};
			{x1 = 5635, y1 = 1285, x2 = 5880, y2 = 1520, map = 1};
}
KnownAreas["Fire"].Guarded = false
KnownAreas["Fire"].SubAreas = {}
	KnownAreas["Fire"].SubAreas["Abyss Champion Spawn"] = {}
	KnownAreas["Fire"].SubAreas["Abyss Champion Spawn"].Prior = true
	KnownAreas["Fire"].SubAreas["Abyss Champion Spawn"].Squares = {
			{x1 = 5814, y1 = 1350, squareCenter = 49, map = 0};
	}
-------------------------------------------------------------------
KnownAreas["Ice"] = {}
KnownAreas["Ice"].MainAreas ={
			{x1 = 5668, y1 = 130, x2 = 5888, y2 = 268, map = 0};
			{x1 = 5800, y1 = 319, x2 = 5863, y2 = 384, map = 0};
			{x1 = 5654, y1 = 300, x2 = 5708, y2 = 340, map = 0};
			{x1 = 5668, y1 = 130, x2 = 5888, y2 = 268, map = 1};
			{x1 = 5800, y1 = 319, x2 = 5863, y2 = 384, map = 1};
			{x1 = 5654, y1 = 300, x2 = 5708, y2 = 340, map = 1};
}
KnownAreas["Ice"].Guarded = false
KnownAreas["Ice"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Corgul Island"] = {}
KnownAreas["Corgul Island"].MainAreas ={
			{x1 = 6384, y1 = 1194, x2 = 6480, y2 = 1300, map = 0};
			{x1 = 6384, y1 = 1194, x2 = 6480, y2 = 1300, map = 1};
}
KnownAreas["Corgul Island"].Guarded = false
KnownAreas["Corgul Island"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Wreck of the Ararat"] = {}
KnownAreas["Wreck of the Ararat"].MainAreas ={
			{x1 = 6255, y1 = 1615, x2 = 6460, y2 = 1800, map = 0};
			{x1 = 6255, y1 = 1615, x2 = 6460, y2 = 1800, map = 1};
}
KnownAreas["Wreck of the Ararat"].Guarded = false
KnownAreas["Wreck of the Ararat"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Castle Blackthorn Dungeon"] = {}
KnownAreas["Castle Blackthorn Dungeon"].MainAreas ={
			{x1 = 6155, y1 = 2300, x2 = 6500, y2 = 2800, map = 0};
			{x1 = 6155, y1 = 2300, x2 = 6500, y2 = 2800, map = 1};
}
KnownAreas["Castle Blackthorn Dungeon"].Guarded = false
KnownAreas["Castle Blackthorn Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Rat Fort"] = {}
KnownAreas["Rat Fort"].MainAreas ={
			{x1 = 616, y1 = 792, x2 = 672, y2 = 848, map = 2};
			{x1 = 164, y1 = 741, x2 = 182, y2 = 759, map = 2, name="Rat Fort Cellar"};
}
KnownAreas["Rat Fort"].Guarded = false
KnownAreas["Rat Fort"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Ancient Citadel"] = {}
KnownAreas["Ancient Citadel"].MainAreas ={
			{x1 = 1448, y1 = 496, x2 = 1552, y2 = 600, map = 2};
}
KnownAreas["Ancient Citadel"].Guarded = false
KnownAreas["Ancient Citadel"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Rock Dungeon"] = {}
KnownAreas["Rock Dungeon"].MainAreas ={
			{x1 = 2176, y1 = 288, x2 = 2200, y2 = 328, map = 2};
			{x1 = 2088, y1 = 6, x2 = 2248, y2 = 184, map = 2};
}
KnownAreas["Rock Dungeon"].Guarded = false
KnownAreas["Rock Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Spider Cave"] = {}
KnownAreas["Spider Cave"].MainAreas ={
			{x1 = 1752, y1 = 952, x2 = 1864, y2 = 1000, map = 2};
			{x1 = 1480, y1 = 864, x2 = 1528, y2 = 896, map = 2};
}
KnownAreas["Spider Cave"].Guarded = false
KnownAreas["Spider Cave"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Spectre Dungeon"] = {}
KnownAreas["Spectre Dungeon"].MainAreas ={
			{x1 = 1936, y1 = 1000, x2 = 2032, y2 = 1120, map = 2};
}
KnownAreas["Spectre Dungeon"].Guarded = false
KnownAreas["Spectre Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Blood Dungeon"] = {}
KnownAreas["Blood Dungeon"].MainAreas ={
			{x1 = 2032, y1 = 808, x2 = 2200, y2 = 1064, map = 2};
}
KnownAreas["Blood Dungeon"].Guarded = false
KnownAreas["Blood Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Ratman Cave"] = {}
KnownAreas["Ratman Cave"].MainAreas ={
			{x1 = 1144, y1 = 1440, x2 = 1368, y2 = 1584, map = 2};
			{x1 = 1264, y1 = 1448, x2 = 1360, y2 = 1552, map = 2};
			{x1 = 1152, y1 = 1456, x2 = 1256, y2 = 1560, map = 2};
}
KnownAreas["Ratman Cave"].Guarded = false
KnownAreas["Ratman Cave"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Serpentine Passage"] = {}
KnownAreas["Serpentine Passage"].MainAreas ={
			{x1 = 368, y1 = 1488, x2 = 560, y2 = 1592, map = 2};
}
KnownAreas["Serpentine Passage"].Guarded = false
KnownAreas["Serpentine Passage"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Ankh Dungeon"] = {}
KnownAreas["Ankh Dungeon"].MainAreas ={
			{x1 = 0, y1 = 1248, x2 = 176, y2 = 1592, map = 2};
			{x1 = 568, y1 = 1152, x2 = 584, y2 = 1160, map = 2};
}
KnownAreas["Ankh Dungeon"].Guarded = false
KnownAreas["Ankh Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Kirin passage"] = {}
KnownAreas["Kirin passage"].MainAreas ={
			{x1 = 0, y1 = 800, x2 = 192, y2 = 1200, map = 2};
}
KnownAreas["Kirin passage"].Guarded = false
KnownAreas["Kirin passage"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Lizard passage"] = {}
KnownAreas["Lizard passage"].MainAreas ={
			{x1 = 256, y1 = 1560, x2 = 336, y2 = 1592, map = 2};
}
KnownAreas["Lizard passage"].Guarded = false
KnownAreas["Lizard passage"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Ancient Lair"] = {}
KnownAreas["Ancient Lair"].MainAreas ={
			{x1 = 204, y1 = 1332, x2 = 245, y2 = 1382, map = 2};
}
KnownAreas["Ancient Lair"].Guarded = false
KnownAreas["Ancient Lair"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Wisp Dungeon"] = {}
KnownAreas["Wisp Dungeon"].MainAreas ={
			{x1 = 619, y1 = 1484, x2 = 737, y2 = 1579, map = 2};
}
KnownAreas["Wisp Dungeon"].Guarded = false
KnownAreas["Wisp Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Sorcerer's Dungeon"] = {}
KnownAreas["Sorcerer's Dungeon"].MainAreas ={
			{x1 = 744, y1 = 1429, x2 = 914, y2 = 1593, map = 2};
}
KnownAreas["Sorcerer's Dungeon"].Guarded = false
KnownAreas["Sorcerer's Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Cyclops Temple"] = {}
KnownAreas["Cyclops Temple"].MainAreas ={
			{x1 = 880, y1 = 1256, x2 = 936, y2 = 1368, map = 2};
			{x1 = 917, y1 = 1422, x2 = 1017, y2 = 1585, map = 2};
}
KnownAreas["Cyclops Temple"].Guarded = false
KnownAreas["Cyclops Temple"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Lord Blackthorn's Castle"] = {}
KnownAreas["Lord Blackthorn's Castle"].MainAreas ={
			{x1 = 1048, y1 = 616, x2 = 1120, y2 = 688, map = 2};
			{x1 = 1080, y1 = 688, x2 = 1104, y2 = 712, map = 2};
}
KnownAreas["Lord Blackthorn's Castle"].Guarded = false
KnownAreas["Lord Blackthorn's Castle"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Savage Camp"] = {}
KnownAreas["Savage Camp"].MainAreas ={
			{x1 = 1189, y1 = 661, x2 = 1293, y2 = 721, map = 2};
			{x1 = 1189, y1 = 721, x2 = 1320, y2 = 800, map = 2};
}
KnownAreas["Savage Camp"].Guarded = false
KnownAreas["Savage Camp"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Meer Catacombs"] = {}
KnownAreas["Meer Catacombs"].MainAreas ={
			{x1 = 1752, y1 = 40, x2 = 1822, y2 = 94, map = 2};
}
KnownAreas["Meer Catacombs"].Guarded = false
KnownAreas["Meer Catacombs"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Meer Village"] = {}
KnownAreas["Meer Village"].MainAreas ={
			{x1 = 1164, y1 = 1087, x2 = 1241, y2 = 1201, map = 2};
}
KnownAreas["Meer Village"].Guarded = false
KnownAreas["Meer Village"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Volcanic Lair"] = {}
KnownAreas["Volcanic Lair"].MainAreas ={
			{x1 = 24, y1 = 664, x2 = 136, y2 = 760, map = 2};
}
KnownAreas["Volcanic Lair"].Guarded = false
KnownAreas["Volcanic Lair"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Exodus Dungeon"] = {}
KnownAreas["Exodus Dungeon"].MainAreas ={
			{x1 = 1832, y1 = 16, w = 248, h = 200, map = 2};
}
KnownAreas["Exodus Dungeon"].Guarded = false
KnownAreas["Exodus Dungeon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Britain Sewers"] = {}
KnownAreas["Britain Sewers"].MainAreas ={
			{x1 = 6030, y1 = 1422, w = 115, h = 90, map = 0};
			{x1 = 6116, y1 = 1392, w = 29, h = 30, map = 0};
			
			{x1 = 6030, y1 = 1422, w = 115, h = 90, map = 1};
			{x1 = 6116, y1 = 1392, w = 29, h = 30, map = 1};
}
KnownAreas["Britain Sewers"].Guarded = false
KnownAreas["Britain Sewers"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Delucia Passage"] = {}
KnownAreas["Delucia Passage"].MainAreas ={
			{x1 = 5888, y1 = 1285, w = 158, h = 137, map = 0};
			{x1 = 5888, y1 = 1285, w = 158, h = 137, map = 1};
}
KnownAreas["Delucia Passage"].Guarded = false
KnownAreas["Delucia Passage"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Tomb of Maabus"] = {}
KnownAreas["Tomb of Maabus"].MainAreas ={
			{x1 = 2018, y1 = 1222, x2 = 2029, y2 = 1239, map = 3};
}
KnownAreas["Tomb of Maabus"].Guarded = false
KnownAreas["Tomb of Maabus"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Hanse's Hostel"] = {}
KnownAreas["Hanse's Hostel"].MainAreas ={
			{x1 = 1049, y1 = 1420, x2 = 1062, y2 = 1445, map = 3};
			{x1 = 1062, y1 = 1420, x2 = 1065, y2 = 1431, map = 3};
			{x1 = 1062, y1 = 1439, x2 = 1065, y2 = 1445, map = 3};
}
KnownAreas["Hanse's Hostel"].Guarded = false
KnownAreas["Hanse's Hostel"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Grand Arena"] = {}
KnownAreas["Grand Arena"].MainAreas ={
			{x1 = 919, y1 = 622, x2 = 962, y2 = 652, map = 3};
}
KnownAreas["Grand Arena"].Guarded = false
KnownAreas["Grand Arena"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Fan Dancer's Dojo"] = {}
KnownAreas["Fan Dancer's Dojo"].MainAreas ={
			{x1 = 40, y1 = 320, x2 = 210, y2 = 720, map = 3};
}
KnownAreas["Fan Dancer's Dojo"].Guarded = false
KnownAreas["Fan Dancer's Dojo"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Yomotsu Mines"] = {}
KnownAreas["Yomotsu Mines"].MainAreas ={
			{x1 = 0, y1 = 0, x2 = 129, y2 = 129, map = 3};
}
KnownAreas["Yomotsu Mines"].Guarded = false
KnownAreas["Yomotsu Mines"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Bedlam"] = {}
KnownAreas["Bedlam"].MainAreas ={
			{x1 = 80, y1 = 1590, x2 = 210, y2 = 1690, map = 3};
}
KnownAreas["Bedlam"].Guarded = false
KnownAreas["Bedlam"].SubAreas = {}
	KnownAreas["Bedlam"].SubAreas["Pestilence Champion Spawn"] = {}
	KnownAreas["Bedlam"].SubAreas["Pestilence Champion Spawn"].Prior = true
	KnownAreas["Bedlam"].SubAreas["Pestilence Champion Spawn"].Squares = {
			{x1 = 174, y1 = 1629, squareCenter = 24, map = 3};
	}
-------------------------------------------------------------------
KnownAreas["Citadel"] = {}
KnownAreas["Citadel"].MainAreas ={
			{x1 = 65, y1 = 1865, x2 = 195, y2 = 1990, map = 3};
}
KnownAreas["Citadel"].Guarded = false
KnownAreas["Citadel"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Labyrinth"] = {}
KnownAreas["Labyrinth"].MainAreas ={
			{x1 = 256, y1 = 1795, x2 = 499, y2 = 2025, map = 3};
}
KnownAreas["Labyrinth"].Guarded = false
KnownAreas["Labyrinth"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Doom"] = {}
KnownAreas["Doom"].MainAreas ={
			{x1 = 256, y1 = 0, x2 = 512, y2 = 304, map = 3};
}
KnownAreas["Doom"].Guarded = false
KnownAreas["Doom"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Doom Gauntlet"] = {}
KnownAreas["Doom Gauntlet"].MainAreas ={
			{x1 = 256, y1 = 304, x2 = 512, y2 = 560, map = 3};
}
KnownAreas["Doom Gauntlet"].Guarded = false
KnownAreas["Doom Gauntlet"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Orc Fortress"] = {}
KnownAreas["Orc Fortress"].MainAreas ={
			{x1 = 1295, y1 = 1189, x2 = 1395, y2 = 1294, map = 3};
}
KnownAreas["Orc Fortress"].Guarded = false
KnownAreas["Orc Fortress"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Holy City"] = {}
KnownAreas["Holy City"].MainAreas ={
			{x1 = 930, y1 = 3840, x2 = 1180, y2 = 4090, map = 5};
}
KnownAreas["Holy City"].Guarded = false
KnownAreas["Holy City"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Underworld"] = {}
KnownAreas["Underworld"].MainAreas ={
		{x1 = 970, y1 = 938, x2 = 1250, y2 = 1216, map = 5};
		{x1 = 1152, y1 = 827, x2 = 1216, y2 = 900, map = 5};
}
KnownAreas["Underworld"].Guarded = false
KnownAreas["Underworld"].SubAreas = {}
		KnownAreas["Underworld"].SubAreas["Experimental Room"] = {}
		KnownAreas["Underworld"].SubAreas["Experimental Room"].Squares = {
				{x1 = 976, y1 = 1073, x2 = 1000, y2 = 1115, map = 5};
		};
		KnownAreas["Underworld"].SubAreas["Deathtrap Hallway"] = {}
		KnownAreas["Underworld"].SubAreas["Deathtrap Hallway"].Squares = {
				{x1 = 1057, y1 = 988, x2 = 1063, y2 = 1066, map = 5};
				{x1 = 1063, y1 = 1054, x2 = 1077, y2 = 1065, map = 5};
				{x1 = 1063, y1 = 1021, x2 = 1073, y2 = 1031, map = 5};
		};
-------------------------------------------------------------------
KnownAreas["Stygian Abyss"] = {}
KnownAreas["Stygian Abyss"].MainAreas ={
		{x1 = 286, y1 = 430, x2 = 714, y2 = 1018, map = 5};
		{x1 = 640, y1 = 268, x2 = 1116, y2 = 812, map = 5};
		{x1 = 774, y1 = 37, x2 = 1098, y2 = 347, map = 5};
		{x1 = 6864, y1 = 620, x2 = 7168, y2 = 1388, map = 0};
}
KnownAreas["Stygian Abyss"].Guarded = false
KnownAreas["Stygian Abyss"].SubAreas = {}	
		KnownAreas["Stygian Abyss"].SubAreas["Secret Garden"] = {}
		KnownAreas["Stygian Abyss"].SubAreas["Secret Garden"].Squares = {
				{x1 = 303, y1 = 575, x2 = 383, y2 = 657, map = 5};
		};
-------------------------------------------------------------------
KnownAreas["Tomb of the Kings"] = {}
KnownAreas["Tomb of the Kings"].MainAreas ={
		{x1 = 0, y1 = 0, x2 = 202, y2 = 255, map = 5};
}
KnownAreas["Tomb of the Kings"].Guarded = false
KnownAreas["Tomb of the Kings"].SubAreas = {}
		KnownAreas["Tomb of the Kings"].SubAreas["Niporailem's Lair"] = {}
		KnownAreas["Tomb of the Kings"].SubAreas["Niporailem's Lair"].Squares = {
				{x1 = 120, y1 = 133, x2 = 183, y2 = 192, map = 5};
		};
-------------------------------------------------------------------
KnownAreas["Navrey's Lair"] = {}
KnownAreas["Navrey's Lair"].MainAreas ={
		{x1 = 1009, y1 = 821, x2 = 1107, y2 = 910, map = 5};
}
KnownAreas["Navrey's Lair"].Guarded = false
KnownAreas["Navrey's Lair"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Medusa's Lair"] = {}
KnownAreas["Medusa's Lair"].MainAreas ={
		{x1 = 754, y1 = 887, x2 = 863, y2 = 1307, map = 5};
}
KnownAreas["Medusa's Lair"].Guarded = false
KnownAreas["Medusa's Lair"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Stygian Dragon's Lair"] = {}
KnownAreas["Stygian Dragon's Lair"].MainAreas ={
		{x1 = 0, y1 = 284, x2 = 148, y2 = 866, map = 5};
		{x1 = 258, y1 = 70, x2 = 494, y2 = 250, map = 5};
}
KnownAreas["Stygian Dragon's Lair"].Guarded = false
KnownAreas["Stygian Dragon's Lair"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Star Room"] = {}
KnownAreas["Star Room"].MainAreas ={
		{x1 = 5131, y1 = 1753, x2 = 5162, y2 = 1783, map = 0};
		{x1 = 5131, y1 = 1753, x2 = 5162, y2 = 1783, map = 1};
}
KnownAreas["Star Room"].Guarded = false
KnownAreas["Star Room"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Fishermen Village"] = {}
KnownAreas["Fishermen Village"].MainAreas ={
		{x1 = 572, y1 = 2999, x2 = 669, y2 = 3067, map = 5};
}
KnownAreas["Fishermen Village"].Guarded = false
KnownAreas["Fishermen Village"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Sleeping Dragon"] = {}
KnownAreas["Sleeping Dragon"].MainAreas ={
		{x1 = 900, y1 = 384, x2 = 996, y2 = 458, map = 4};
}
KnownAreas["Sleeping Dragon"].Guarded = false
KnownAreas["Sleeping Dragon"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Valor Champion Spawn"] = {}
KnownAreas["Valor Champion Spawn"].MainAreas ={
		{x1 = 336, y1 = 281, x2 = 432, y2 = 377, map = 2};
}
KnownAreas["Valor Champion Spawn"].Guarded = false
KnownAreas["Valor Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Humility Champion Spawn"] = {}
KnownAreas["Humility Champion Spawn"].MainAreas ={
		{x1 = 414, y1 = 878, x2 = 510, y2 = 974, map = 2};
}
KnownAreas["Humility Champion Spawn"].Guarded = false
KnownAreas["Humility Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Forest Lord Champion Spawn"] = {}
KnownAreas["Forest Lord Champion Spawn"].MainAreas ={
		{x1 = 1597, y1 = 1067, x2 = 1693, y2 = 1133, map = 2};
		{x1 = 5559, y1 = 3757, squareCenter = 49, map = 0};
}
KnownAreas["Forest Lord Champion Spawn"].Guarded = false
KnownAreas["Forest Lord Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Desert Champion Spawn"] = {}
KnownAreas["Desert Champion Spawn"].MainAreas ={
		{x1 = 5636, y1 = 2916, squareCenter = 49, map = 0};
}
KnownAreas["Desert Champion Spawn"].Guarded = false
KnownAreas["Desert Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Tortoise Champion Spawn"] = {}
KnownAreas["Tortoise Champion Spawn"].MainAreas ={
		{x1 = 5724, y1 = 3991, squareCenter = 49, map = 0};
}
KnownAreas["Tortoise Champion Spawn"].Guarded = false
KnownAreas["Tortoise Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Ice West Champion Spawn"] = {}
KnownAreas["Ice West Champion Spawn"].MainAreas ={
		{x1 = 5511, y1 = 2360, squareCenter = 49, map = 0};
}
KnownAreas["Ice West Champion Spawn"].Guarded = false
KnownAreas["Ice West Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Oasis Champion Spawn"] = {}
KnownAreas["Oasis Champion Spawn"].MainAreas ={
		{x1 = 5549, y1 = 2640, squareCenter = 49, map = 0};
}
KnownAreas["Oasis Champion Spawn"].Guarded = false
KnownAreas["Oasis Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Terra Sanctum Champion Spawn"] = {}
KnownAreas["Terra Sanctum Champion Spawn"].MainAreas ={
		{x1 = 6035, y1 = 2944, squareCenter = 49, map = 0};
}
KnownAreas["Terra Sanctum Champion Spawn"].Guarded = false
KnownAreas["Terra Sanctum Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Marble Champion Spawn"] = {}
KnownAreas["Marble Champion Spawn"].MainAreas ={
		{x1 = 5267, y1 = 3171, squareCenter = 49, map = 0};
}
KnownAreas["Marble Champion Spawn"].Guarded = false
KnownAreas["Marble Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Hopper Bog Champion Spawn"] = {}
KnownAreas["Hopper Bog Champion Spawn"].MainAreas ={
		{x1 = 5954, y1 = 3475, squareCenter = 49, map = 0};
}
KnownAreas["Hopper Bog Champion Spawn"].Guarded = false
KnownAreas["Hopper Bog Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Khaldun Champion Spawn"] = {}
KnownAreas["Khaldun Champion Spawn"].MainAreas ={
		{x1 = 5982, y1 = 3882, squareCenter = 49, map = 0};
}
KnownAreas["Khaldun Champion Spawn"].Guarded = false
KnownAreas["Khaldun Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Ice East Champion Spawn"] = {}
KnownAreas["Ice East Champion Spawn"].MainAreas ={
		{x1 = 6038, y1 = 2400, squareCenter = 49, map = 0};
}
KnownAreas["Ice East Champion Spawn"].Guarded = false
KnownAreas["Ice East Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Damwin Champion Spawn"] = {}
KnownAreas["Damwin Champion Spawn"].MainAreas ={
		{x1 = 5281, y1 = 3368, squareCenter = 49, map = 0};
}
KnownAreas["Damwin Champion Spawn"].Guarded = false
KnownAreas["Damwin Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["City of Death Champion Spawn"] = {}
KnownAreas["City of Death Champion Spawn"].MainAreas ={
		{x1 = 5207, y1 = 3637, squareCenter = 49, map = 0};
}
KnownAreas["City of Death Champion Spawn"].Guarded = false
KnownAreas["City of Death Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Abyssal Infernal Champion Spawn"] = {}
KnownAreas["Abyssal Infernal Champion Spawn"].MainAreas ={
		{x1 = 6995, y1 = 733, squareCenter = 49, map = 0};
}
KnownAreas["Abyssal Infernal Champion Spawn"].Guarded = false
KnownAreas["Abyssal Infernal Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Primeval Lich Champion Spawn"] = {}
KnownAreas["Primeval Lich Champion Spawn"].MainAreas ={
		{x1 = 7000, y1 = 1008, squareCenter = 49, map = 0};
}
KnownAreas["Primeval Lich Champion Spawn"].Guarded = false
KnownAreas["Primeval Lich Champion Spawn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Luna"] = {}
KnownAreas["Luna"].MainAreas ={
			{x1 = 903, y1 = 447, x2 = 1080, y2 = 592, map = 3};
}
KnownAreas["Luna"].Guarded = false
KnownAreas["Luna"].SubAreas = {}
	KnownAreas["Luna"].SubAreas["Guarded Area"] = {}
	KnownAreas["Luna"].SubAreas["Guarded Area"].Guarded = true
	KnownAreas["Luna"].SubAreas["Guarded Area"].Squares = {
			{x1 = 945, y1 = 490, x2 = 1036, y2 = 551, map = 3, name="Luna - Inner Town"};
	}
	KnownAreas["Luna"].SubAreas["Tavern"] = {}
	KnownAreas["Luna"].SubAreas["Tavern"].Prior = true
	KnownAreas["Luna"].SubAreas["Tavern"].Squares = {
			{x1 = 985, y1 = 511, x2 = 1004, y2 = 530, z = -30, map = 3, name="Paladin's Stopover"};
	}
	KnownAreas["Luna"].SubAreas["Shops"] = {}
	KnownAreas["Luna"].SubAreas["Shops"].Prior = true
	KnownAreas["Luna"].SubAreas["Shops"].Squares = {
			{x1 = 1000, y1 = 509, x2 = 1005, y2 = 516, z = -50, map = 3, name="Hardwoods and More"};
			{x1 = 1000, y1 = 523, x2 = 1005, y2 = 531, z = -50, map = 3, name="Sage's Refuge"};
			{x1 = 973, y1 = 523, x2 = 979, y2 = 531, z = -50, map = 3, name="Clothier's Colors"};
			{x1 = 973, y1 = 509, x2 = 979, y2 = 516, z = -50, map = 3, name="Shining Blades"};
			{x1 = 1022, y1 = 492, x2 = 1031, y2 = 501, z = -70, map = 3, name="Proud Bridle"};
	}
	KnownAreas["Luna"].SubAreas["Banks"] = {}
	KnownAreas["Luna"].SubAreas["Banks"].Prior = true
	KnownAreas["Luna"].SubAreas["Banks"].Squares = {
			{x1 = 985, y1 = 516, x2 = 994, y2 = 523, z = -50, map = 3, name="Luna Bank"};
	}
-------------------------------------------------------------------
KnownAreas["Umbra"] = {}
KnownAreas["Umbra"].MainAreas ={
			{x1 = 2042, y1 = 1265, x2 = 2090, y2 = 1278, map = 3};
			{x1 = 1960, y1 = 1278, x2 = 2106, y2 = 1413, map = 3};
			{x1 = 2004, y1 = 1413, x2 = 2040, y2 = 1419, map = 3};
			{x1 = 1940, y1 = 1348, x2 = 2051, y2 = 1426, map = 3};
}
KnownAreas["Umbra"].Guarded = true
KnownAreas["Umbra"].SubAreas = {}
	KnownAreas["Umbra"].SubAreas["Tavern"] = {}
	KnownAreas["Umbra"].SubAreas["Tavern"].Squares = {
			{x1 = 2031, y1 = 1311, x2 = 2046, y2 = 1325, map = 3, name="Wailing Banshee Inn"};
			{x1 = 2027, y1 = 1349, x2 = 2029, y2 = 1357, map = 3, name="Skeleton Swill"};
	}
	KnownAreas["Umbra"].SubAreas["Banks"] = {}
	KnownAreas["Umbra"].SubAreas["Banks"].Squares = {
			{x1 = 2042, y1 = 1337, x2 = 2054, y2 = 1349, map = 3, name="Umbra Bank"};
	}
	KnownAreas["Umbra"].SubAreas["Shops"] = {}
	KnownAreas["Umbra"].SubAreas["Shops"].Squares = {
			{x1 = 1974, y1 = 1351, x2 = 1999, y2 = 1372, map = 3, name="Armoury of Souls"};
			{x1 = 2013, y1 = 1350, x2 = 2024, y2 = 1368, map = 3, name="Ghast Refectory"};
			{x1 = 2057, y1 = 1278, x2 = 2072, y2 = 1297, map = 3, name="Warped Woodworks"};
			{x1 = 2072, y1 = 1316, x2 = 2091, y2 = 1338, map = 3, name="Darkweave"};
			{x1 = 2065, y1 = 1369, x2 = 2094, y2 = 1378, map = 3, name="Bloodletter's Guild"};
			{x1 = 2045, y1 = 1393, x2 = 2057, y2 = 1404, map = 3, name="Lich's Hoard"};
			{x1 = 2017, y1 = 1371, x2 = 2040, y2 = 1393, map = 3, name="Necromancer Amphitheater"};
			{x1 = 2007, y1 = 1319, x2 = 2024, y2 = 1336, map = 3, name="Gravedigger's Apparatus"};
			{x1 = 1988, y1 = 1310, x2 = 2001, y2 = 1323, map = 3, name="Critter Pens"};
	}
-------------------------------------------------------------------
KnownAreas["Royal City"] = {}
KnownAreas["Royal City"].MainAreas ={
			{x1 = 624, y1 = 3296, x2 = 927, y2 = 3583, map = 5};
}
KnownAreas["Royal City"].Guarded = true
KnownAreas["Royal City"].SubAreas = {}
	KnownAreas["Royal City"].SubAreas["Tavern"] = {}
	KnownAreas["Royal City"].SubAreas["Tavern"].Squares = {
			{x1 = 724, y1 = 3464, x2 = 760, y2 = 3482, map = 5, name="Inn"};
			{x1 = 748, y1 = 3482, x2 = 759, y2 = 3491, map = 5, name="Inn"};
	}
	KnownAreas["Royal City"].SubAreas["Royal Palace"] = {}
	KnownAreas["Royal City"].SubAreas["Royal Palace"].Squares = {
			{x1 = 720, y1 = 3342, x2 = 782, y2 = 3405, map = 5};
	}
	KnownAreas["Royal City"].SubAreas["Banks"] = {}
	KnownAreas["Royal City"].SubAreas["Banks"].Squares = {
			{x1 = 831, y1 = 3432, x2 = 850, y2 = 3445, map = 5, name="Royal Bank"};
	}
	KnownAreas["Royal City"].SubAreas["Shops"] = {}
	KnownAreas["Royal City"].SubAreas["Shops"].Squares = {
			{x1 = 801, y1 = 3489, x2 = 810, y2 = 3497, map = 5, name="Baker"};
			{x1 = 791, y1 = 3488, x2 = 800, y2 = 3497, map = 5, name="Provisioner"};
			{x1 = 779, y1 = 3488, x2 = 788, y2 = 3498, map = 5, name="Healer"};
			{x1 = 769, y1 = 3483, x2 = 777, y2 = 3497, map = 5, name="Mage"};
			{x1 = 769, y1 = 3472, x2 = 777, y2 = 3481, map = 5, name="Alchemist"};
			{x1 = 769, y1 = 3462, x2 = 777, y2 = 3470, map = 5, name="Library"};
			{x1 = 695, y1 = 3520, x2 = 730, y2 = 3532, map = 5, name="Schoolyard"};
			{x1 = 695, y1 = 3500, x2 = 707, y2 = 3520, map = 5, name="Schoolyard"};
			{x1 = 775, y1 = 3427, x2 = 784, y2 = 3435, map = 5, name="Jeweler"};
			{x1 = 808, y1 = 3417, x2 = 823, y2 = 3422, map = 5, name="Blacksmith"};
			{x1 = 814, y1 = 3424, x2 = 823, y2 = 3432, map = 5, name="Carpenter"};
			{x1 = 814, y1 = 3434, x2 = 823, y2 = 3442, map = 5, name="Tinker"};
			{x1 = 846, y1 = 3400, x2 = 858, y2 = 3416, map = 5, name="Ter Mur Stables"};
			{x1 = 802, y1 = 3384, x2 = 810, y2 = 3392, map = 5, name="Tanner"};
			{x1 = 802, y1 = 3394, x2 = 810, y2 = 3403, map = 5, name="Tailor"};
			{x1 = 650, y1 = 3399, x2 = 674, y2 = 3433, map = 5, name="Museum of Wanders"};
	}
-------------------------------------------------------------------
KnownAreas["Zento"] = {}
KnownAreas["Zento"].MainAreas ={
			{x1 = 657, y1 = 1193, x2 = 814, y2 = 1318, map = 4};
}
KnownAreas["Zento"].Guarded = true
KnownAreas["Zento"].SubAreas = {}
	KnownAreas["Zento"].SubAreas["Tavern"] = {}
	KnownAreas["Zento"].SubAreas["Tavern"].Squares = {
			{x1 = 675, y1 = 1202, x2 = 684, y2 = 1218, map = 4, name="Sake Saka Tavern and Miyabi Inn"};
			{x1 = 685, y1 = 1202, x2 = 701, y2 = 1227, map = 4, name="Sake Saka Tavern and Miyabi Inn"};
	}
	KnownAreas["Zento"].SubAreas["Banks"] = {}
	KnownAreas["Zento"].SubAreas["Banks"].Squares = {
			{x1 = 727, y1 = 1247, x2 = 736, y2 = 1256, map = 4, name="Bank"};
	}
	KnownAreas["Zento"].SubAreas["Shops"] = {}
	KnownAreas["Zento"].SubAreas["Shops"].Squares = {
			{x1 = 776, y1 = 1213, x2 = 786, y2 = 1225, map = 4, name="Satori Healing Garden"};
			{x1 = 764, y1 = 1243, x2 = 785, y2 = 1265, map = 4, name="Mibu BlackSmith"};
			{x1 = 770, y1 = 1271, x2 = 794, y2 = 1282, map = 4, name="Yume Stables"};
			{x1 = 776, y1 = 1296, x2 = 787, y2 = 1310, map = 4, name="Kagome Bowyer"};
			{x1 = 736, y1 = 1296, x2 = 767, y2 = 1310, map = 4, name="Iroha Armorer and Musha-Shugyo Dojo"};
			{x1 = 725, y1 = 1280, x2 = 734, y2 = 1284, map = 4, name="Zento Provides"};
			{x1 = 717, y1 = 1293, x2 = 722, y2 = 1299, map = 4, name="Good Fortunes Jewelry"};
			{x1 = 723, y1 = 1293, x2 = 731, y2 = 1312, map = 4, name="Good Fortunes Jewelry"};
			{x1 = 672, y1 = 1293, x2 = 705, y2 = 1303, map = 4, name="Sasara Magical Supplies and Remedies"};
			{x1 = 605, y1 = 1245, x2 = 694, y2 = 1278, map = 4, name="Rokuon Cultural Center and Shops"};
			{x1 = 699, y1 = 1245, x2 = 708, y2 = 1279, map = 4, name="Koku Kitchens"};
			{x1 = 717, y1 = 1202, x2 = 750, y2 = 1227, map = 4, name="Suteki Na Craftworks"};
			{x1 = 799, y1 = 1201, x2 = 805, y2 = 1207, map = 4, name="Makoto Jima Moongate"};			
	}
-------------------------------------------------------------------
KnownAreas["Ver Lor Reg"] = {}
KnownAreas["Ver Lor Reg"].MainAreas ={
			{x1 = 824, y1 = 552, x2 = 856, y2 = 728, map = 2};
			{x1 = 752, y1 = 576, x2 = 824, y2 = 704, map = 2};
			{x1 = 856, y1 = 576, x2 = 904, y2 = 704, map = 2};
			{x1 = 904, y1 = 624, x2 = 925, y2 = 656, map = 2};
}
KnownAreas["Ver Lor Reg"].Guarded = true
KnownAreas["Ver Lor Reg"].SubAreas = {}
	KnownAreas["Ver Lor Reg"].SubAreas["Tavern"] = {}
	KnownAreas["Ver Lor Reg"].SubAreas["Tavern"].Squares = {
			{x1 = 827, y1 = 701, x2 = 851, y2 = 727, map = 2, name="Ter-Zu"};
	}
	KnownAreas["Ver Lor Reg"].SubAreas["Banks"] = {}
	KnownAreas["Ver Lor Reg"].SubAreas["Banks"].Squares = {
			{x1 = 844, y1 = 678, x2 = 859, y2 = 685, map = 2, name="Bank"};
			{x1 = 852, y1 = 670, x2 = 859, y2 = 677, map = 2, name="Bank"};
			{x1 = 844, y1 = 598, x2 = 859, y2 = 605, map = 2, name="Bank"};
			{x1 = 852, y1 = 606, x2 = 859, y2 = 613, map = 2, name="Bank"};
	}
	KnownAreas["Ver Lor Reg"].SubAreas["Shops"] = {}
	KnownAreas["Ver Lor Reg"].SubAreas["Shops"].Squares = {
			{x1 = 853, y1 = 696, x2 = 875, y2 = 701, map = 2, name="Klar-Lap-In-Lem"};
			{x1 = 868, y1 = 679, x2 = 875, y2 = 693, map = 2, name="Lap-In-Lem"};
			{x1 = 877, y1 = 670, x2 = 899, y2 = 677, map = 2, name="Ter-An-Esk-Por"};
			{x1 = 892, y1 = 655, x2 = 899, y2 = 670, map = 2, name="Ter-An-Esk-Por"};
			{x1 = 877, y1 = 606, x2 = 899, y2 = 613, map = 2, name="Skis-In-Lem"};
			{x1 = 892, y1 = 614, x2 = 899, y2 = 628, map = 2, name="Skis-In-Lem"};
			{x1 = 853, y1 = 582, x2 = 875, y2 = 589, map = 2, name="In-Mani-Lem"};
			{x1 = 868, y1 = 590, x2 = 875, y2 = 604, map = 2, name="In-Mani-Lem"};
			{x1 = 828, y1 = 558, x2 = 851, y2 = 580, map = 2, name="Ter-Ort-Lem"};
			{x1 = 804, y1 = 582, x2 = 826, y2 = 589, map = 2, name="Agra-Char-In-Lem"};
			{x1 = 804, y1 = 590, x2 = 811, y2 = 604, map = 2, name="Agra-Char-In-Lem"};
			{x1 = 780, y1 = 606, x2 = 802, y2 = 628, map = 2, name="Lap-In-Lem"};
			{x1 = 756, y1 = 630, x2 = 778, y2 = 653, map = 2, name="Atri-Ben-In-Ailem"};
			{x1 = 780, y1 = 655, x2 = 801, y2 = 677, map = 2, name="Zhel-In-Lem"};
			{x1 = 820, y1 = 598, x2 = 826, y2 = 612, map = 2, name="Ben-In-Lem"};
			{x1 = 828, y1 = 598, x2 = 835, y2 = 605, map = 2, name="Ben-In-Lem"};
			{x1 = 820, y1 = 670, x2 = 827, y2 = 685, map = 2, name="Ben-In-Lem"};
			{x1 = 828, y1 = 678, x2 = 835, y2 = 685, map = 2, name="Ben-In-Lem"};
			{x1 = 804, y1 = 679, x2 = 811, y2 = 698, map = 2, name="Aglo-In-Lem"};
			{x1 = 812, y1 = 694, x2 = 826, y2 = 701, map = 2, name="Aglo-In-Lem"};
			{x1 = 857, y1 = 622, x2 = 880, y2 = 629, map = 2, name="Librum"};
			{x1 = 857, y1 = 654, x2 = 880, y2 = 661, map = 2, name="Librum"};
	}
-------------------------------------------------------------------
KnownAreas["Mistas"] = {}
KnownAreas["Mistas"].MainAreas ={
			{x1 = 744, y1 = 984, x2 = 912, y2 = 1152, map = 2};
			{x1 = 744, y1 = 1152, x2 = 792, y2 = 1176, map = 2};
}
KnownAreas["Mistas"].Guarded = false
KnownAreas["Mistas"].SubAreas = {}
	KnownAreas["Mistas"].SubAreas["Tavern"] = {}
	KnownAreas["Mistas"].SubAreas["Tavern"].Squares = {
			{x1 = 752, y1 = 1131, x2 = 768, y2 = 1152, map = 2, name="Mistas Regsit"};
	}
-------------------------------------------------------------------
KnownAreas["Solen Hive"] = {}
KnownAreas["Solen Hive"].MainAreas ={
			{x1 = 5632, y1 = 1775, w = 305, h = 265, map = 0};
			{x1 = 5632, y1 = 1775, w = 305, h = 265, map = 1};
}
KnownAreas["Solen Hive"].Guarded = false
KnownAreas["Solen Hive"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["The Deuce's Vinculum Inn"] = {}
KnownAreas["The Deuce's Vinculum Inn"].MainAreas ={
			{x1 = 658, y1 = 654, x2 = 670, y2 = 677, map = 2};
}
KnownAreas["The Deuce's Vinculum Inn"].Guarded = false
KnownAreas["The Deuce's Vinculum Inn"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Twin Oaks Tavern"] = {}
KnownAreas["Twin Oaks Tavern"].MainAreas ={
			{x1 = 1547, y1 = 1038, x2 = 1564, y2 = 1054, map = 2};
}
KnownAreas["Twin Oaks Tavern"].Guarded = false
KnownAreas["Twin Oaks Tavern"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Arena"] = {}
KnownAreas["Arena"].MainAreas ={
			{x1 = 3744, y1 = 2749, x2 = 3779, y2 = 2780, map = 0, name="Ocllo Arena"};
}
KnownAreas["Arena"].Guarded = false
KnownAreas["Arena"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Graveyards"] = {}
KnownAreas["Graveyards"].MainAreas ={
			{x1 = 4536, y1 = 1297, x2 = 4556, y2 = 1334, map = 0, name="Moonglow Graveyard"};
			{x1 = 4528, y1 = 1314, x2 = 4536, y2 = 1334, map = 0, name="Moonglow Graveyard"};
			{x1 = 1337, y1 = 1444, x2 = 1389, y2 = 1492, map = 0, name="Britain Graveyard"};
			{x1 = 1337, y1 = 1492, x2 = 1374, y2 = 1509, map = 0, name="Britain Graveyard"};
			{x1 = 2432, y1 = 1081, x2 = 2452, y2 = 1117, map = 0, name="Cove Graveyard"};
			{x1 = 2424, y1 = 1098, x2 = 2452, y2 = 1118, map = 0, name="Cove Graveyard"};
			{x1 = 712, y1 = 1104, x2 = 734, y2 = 1134, map = 0, name="Yew Graveyard"};
			{x1 = 1272, y1 = 3712, x2 = 1291, y2 = 3722, map = 0, name="Jhelom Graveyard"};
			{x1 = 1272, y1 = 3723, x2 = 1299, y2 = 3734, map = 0, name="Jhelom Graveyard"};
			{x1 = 1272, y1 = 3735, x2 = 1294, y2 = 3743, map = 0, name="Jhelom Graveyard"};
			{x1 = 1280, y1 = 3743, x2 = 1294, y2 = 3750, map = 0, name="Jhelom Graveyard"};
			{x1 = 2728, y1 = 840, x2 = 2782, y2 = 894, map = 0, name="Vesper Graveyard"};
			
			{x1 = 4536, y1 = 1297, x2 = 4556, y2 = 1334, map = 1, name="Moonglow Graveyard"};
			{x1 = 4528, y1 = 1314, x2 = 4536, y2 = 1334, map = 1, name="Moonglow Graveyard"};
			{x1 = 1337, y1 = 1444, x2 = 1389, y2 = 1492, map = 1, name="Britain Graveyard"};
			{x1 = 1337, y1 = 1492, x2 = 1374, y2 = 1509, map = 1, name="Britain Graveyard"};
			{x1 = 2432, y1 = 1081, x2 = 2452, y2 = 1117, map = 1, name="Cove Graveyard"};
			{x1 = 2424, y1 = 1098, x2 = 2452, y2 = 1118, map = 1, name="Cove Graveyard"};
			{x1 = 712, y1 = 1104, x2 = 734, y2 = 1134, map = 1, name="Yew Graveyard"};
			{x1 = 1272, y1 = 3712, x2 = 1291, y2 = 3722, map = 1, name="Jhelom Graveyard"};
			{x1 = 1272, y1 = 3723, x2 = 1299, y2 = 3734, map = 1, name="Jhelom Graveyard"};
			{x1 = 1272, y1 = 3735, x2 = 1294, y2 = 3743, map = 1, name="Jhelom Graveyard"};
			{x1 = 1280, y1 = 3743, x2 = 1294, y2 = 3750, map = 1, name="Jhelom Graveyard"};
			{x1 = 2728, y1 = 840, x2 = 2782, y2 = 894, map = 1, name="Vesper Graveyard"};
			
			{x1 = 960, y1 = 752, x2 = 974, y2 = 762, map = 1, name="Yew Crypts"};
			{x1 = 960, y1 = 688, x2 = 966, y2 = 762, z = -20, map = 1, name="Yew Crypts"};
			{x1 = 958, y1 = 704, x2 = 968, y2 = 734, z = -40, map = 1, name="Yew Crypts"};
			{x1 = 969, y1 = 724, x2 = 992, y2 = 727, z = -40, map = 1, name="Yew Crypts"};
			{x1 = 960, y1 = 688, x2 = 966, y2 = 718, map = 1, name="Yew Crypts"};
			{x1 = 944, y1 = 697, x2 = 966, y2 = 718, map = 1, name="Yew Crypts"};
			{x1 = 994, y1 = 720, x2 = 1000, y2 = 726, z = -40, map = 1, name="Yew Crypts"};
			{x1 = 994, y1 = 712, x2 = 1000, y2 = 718, z = -20, map = 1, name="Yew Crypts"};
			{x1 = 1001, y1 = 713, x2 = 1022, y2 = 715, z = -20, map = 1, name="Yew Crypts"};
			{x1 = 1014, y1 = 717, x2 = 1022, y2 = 739, z = -40, map = 1, name="Yew Crypts"};
			{x1 = 1016, y1 = 741, x2 = 1019, y2 = 777, z = -40, map = 1, name="Yew Crypts"};
			{x1 = 998, y1 = 757, x2 = 1019, y2 = 777, z = -40, map = 1, name="Yew Crypts"};
			{x1 = 998, y1 = 757, x2 = 1019, y2 = 777, z = -55, map = 1, name="Yew Crypts"};
			{x1 = 998, y1 = 757, x2 = 1019, y2 = 777, z = -60, map = 1, name="Yew Crypts"};
			{x1 = 1014, y1 = 778, x2 = 1020, y2 = 788, z = -40, map = 1, name="Yew Crypts"};
			{x1 = 1006, y1 = 786, x2 = 1012, y2 = 796, z = -20, map = 1, name="Yew Crypts"};
			{x1 = 1006, y1 = 796, x2 = 1012, y2 = 824, z = -20, map = 1, name="Yew Crypts"};
			{x1 = 1006, y1 = 818, x2 = 1012, y2 = 824, map = 1, name="Yew Crypts"};
			{x1 = 1014, y1 = 818, x2 = 1020, y2 = 830, map = 1, name="Yew Crypts"};
			{x1 = 1013, y1 = 787, x2 = 1020, y2 = 788, z = -20, map = 1, name="Yew Crypts"};
			{x1 = 1016, y1 = 787, x2 = 1018, y2 = 788, z = -33, map = 1, name="Yew Crypts"};
			{x1 = 1012, y1 = 693, x2 = 1022, y2 = 721, z = -20, map = 1, name="Yew Crypts"};
			{x1 = 1012, y1 = 693, x2 = 1022, y2 = 721, z = -33, map = 1, name="Yew Crypts"};
			{x1 = 1012, y1 = 693, x2 = 1018, y2 = 710, map = 1, name="Yew Crypts"};
			{x1 = 994, y1 = 719, x2 = 1000, y2 = 721, z = -33, map = 1, name="Yew Crypts"};
			{x1 = 994, y1 = 719, x2 = 1000, y2 = 721, z = -20, map = 1, name="Yew Crypts"};
}
KnownAreas["Graveyards"].Guarded = false
KnownAreas["Graveyards"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Ocllo"] = {}
KnownAreas["Ocllo"].MainAreas ={
			{x1 = 3587, y1 = 2456, w= 119, h=99, map = 0};
			{x1 = 3706, y1 = 2460, w= 2, h=95, map = 0};
			{x1 = 3587, y1 = 2555, w= 106, h=73, map = 0};
			{x1 = 3590, y1 = 2628, w= 103, h=58, map = 0};
			{x1 = 3693, y1 = 2555, w= 61, h=144, map = 0};
			{x1 = 3754, y1 = 2558, w= 7, h=141, map = 0};
			{x1 = 3761, y1 = 2555, w= 7, h=144, map = 0};
			{x1 = 3695, y1 = 2699, w= 66, h=13, map = 0};
}
KnownAreas["Ocllo"].Guarded = true
KnownAreas["Ocllo"].SubAreas = {}
	KnownAreas["Ocllo"].SubAreas["Tavern"] = {}
	KnownAreas["Ocllo"].SubAreas["Tavern"].Squares = {
			{x1 = 3664, y1 = 2608, w= 15, h=15, map = 0, name="The Bountiful Harvest"};
			{x1 = 3672, y1 = 2648, w= 7, h=7, map = 0, name="The Albatros"};
			{x1 = 3664, y1 = 2640, w= 7, h=15, map = 0, name="The Albatros"};
			
	}
	KnownAreas["Ocllo"].SubAreas["Banks"] = {}
	KnownAreas["Ocllo"].SubAreas["Banks"].Squares = {
			{x1 = 3688, y1 = 2504, x2 = 3694, y2 = 2518, map = 0, name="Bank of Ocllo"};
			{x1 = 3695, y1 = 2504, x2 = 3702, y2 = 2510, map = 0, name="Bank of Ocllo"};
	}
	KnownAreas["Ocllo"].SubAreas["Shops"] = {}
	KnownAreas["Ocllo"].SubAreas["Shops"].Squares = {
			{x1 = 3624, y1 = 2632, x2 = 3630, y2 = 2638, map = 0, name="Anchors Aweigh"};
			{x1 = 3632, y1 = 2632, x2 = 3638, y2 = 2646, map = 0, name="Anchors Aweigh"};
			{x1 = 3592, y1 = 2600, x2 = 3598, y2 = 2606, map = 0, name="Better Leather Tannery"};
			{x1 = 3600, y1 = 2600, x2 = 3606, y2 = 2622, map = 0, name="Better Leather Tannery"};
			{x1 = 3624, y1 = 2601, x2 = 3630, y2 = 2614, map = 0, name="Healer of Ocllo"};
			{x1 = 3632, y1 = 2601, x2 = 3638, y2 = 2607, map = 0, name="Healer of Ocllo"};
			{x1 = 3632, y1 = 2592, x2 = 3646, y2 = 2598, map = 0, name="Hammer and Steel Smithy"};
			{x1 = 3656, y1 = 2584, x2 = 3678, y2 = 2590, map = 0, name="A Stitch in Time"};
			{x1 = 3664, y1 = 2576, x2 = 3670, y2 = 2598, map = 0, name="A Stitch in Time"};
			{x1 = 3626, y1 = 2568, x2 = 3670, y2 = 2598, map = 0, name="Last Chance Provisioners"};
			{x1 = 3632, y1 = 2561, x2 = 3638, y2 = 2582, map = 0, name="Last Chance Provisioners"};
			{x1 = 3600, y1 = 2568, x2 = 3606, y2 = 2582, map = 0, name="Now You're Cookin'"};
			{x1 = 3608, y1 = 2568, x2 = 3622, y2 = 2574, map = 0, name="Now You're Cookin'"};
			{x1 = 3616, y1 = 2576, x2 = 3622, y2 = 2582, map = 0, name="Now You're Cookin'"};
			{x1 = 3624, y1 = 2528, x2 = 3638, y2 = 2534, map = 0, name="Sorcers' Guild"};
			{x1 = 3624, y1 = 2536, x2 = 3630, y2 = 2550, map = 0, name="Sorcers' Guild"};
			{x1 = 3632, y1 = 2544, x2 = 3638, y2 = 2550, map = 0, name="Sorcers' Guild"};
			{x1 = 3657, y1 = 2528, x2 = 3670, y2 = 2534, map = 0, name="Bardic Guild"};
			{x1 = 3672, y1 = 2528, x2 = 3677, y2 = 2542, map = 0, name="Bardic Guild"};
			{x1 = 3664, y1 = 2496, x2 = 3670, y2 = 2502, map = 0, name="Counselor's Guild"};
			{x1 = 3656, y1 = 2504, x2 = 3670, y2 = 2510, map = 0, name="Counselor's Guild"};
			{x1 = 3632, y1 = 2496, x2 = 3638, y2 = 2502, map = 0, name="Paint and More"};
			{x1 = 3640, y1 = 2496, x2 = 3645, y2 = 2510, map = 0, name="Paint and More"};
			{x1 = 3608, y1 = 2464, x2 = 3614, y2 = 2471, map = 0, name="Ocllo Public Library"};
			{x1 = 3608, y1 = 2472, x2 = 3622, y2 = 2478, map = 0, name="Ocllo Public Library"};
			{x1 = 3672, y1 = 2472, x2 = 3694, y2 = 2478, map = 0, name="First Academy of Music"};
			{x1 = 3704, y1 = 2584, x2 = 3710, y2 = 2590, map = 0, name="Farm"};
			{x1 = 3736, y1 = 2561, x2 = 3742, y2 = 2566, map = 0, name="Farm"};
			{x1 = 3704, y1 = 2648, x2 = 3718, y2 = 2653, map = 0, name="Sweet Meat"};
			{x1 = 3736, y1 = 2680, x2 = 3742, y2 = 2694, map = 0, name="Farm"};
			{x1 = 3744, y1 = 2680, x2 = 3750, y2 = 2686, map = 0, name="Farm"};
			{x1 = 3728, y1 = 2632, x2 = 3734, y2 = 2638, map = 0, name="Farm"};
	}
-------------------------------------------------------------------
KnownAreas["New Haven"] = {}
KnownAreas["New Haven"].MainAreas ={
			{x1 = 3423, y1 = 2480, w= 121, h=143, map = 1};
			{x1 = 3416, y1 = 2496, x2 = 3478, y2 = 2647, map = 1};
}
KnownAreas["New Haven"].Guarded = true
KnownAreas["New Haven"].SubAreas = {}
	KnownAreas["New Haven"].SubAreas["Tavern"] = {}
	KnownAreas["New Haven"].SubAreas["Tavern"].Squares = {
			{x1 = 3493, y1 = 2513, w= 10, h=10, map = 1, name="Gentle Rest"};
			{x1 = 3503, y1 = 2513, w= 7, h=17, map = 1, name="Gentle Rest"};
	}
	KnownAreas["New Haven"].SubAreas["Banks"] = {}
	KnownAreas["New Haven"].SubAreas["Banks"].Squares = {
			{x1 = 3479, y1 = 2565, x2 = 3490, y2 = 2578, map = 1, name="New Haven Bank"};
			{x1 = 3492, y1 = 2568, x2 = 3494, y2 = 2575, map = 1, name="New Haven Bank"};
	}
	KnownAreas["New Haven"].SubAreas["Shops"] = {}
	KnownAreas["New Haven"].SubAreas["Shops"].Squares = {
			{x1 = 3490, y1 = 2588, x2 = 3495, y2 = 2593, map = 1, name="New Haven Bay Port Authority"};
			{x1 = 3439, y1 = 2632, x2 = 3447, y2 = 2647, map = 1, name="The West Mill"};
			{x1 = 3443, y1 = 2601, x2 = 3448, y2 = 2610, map = 1, name="Thick Hide"};
			{x1 = 3407, y1 = 2597, x2 = 3420, y2 = 2606, map = 1, name="The Proscenium"};
			{x1 = 3408, y1 = 2607, x2 = 3413, y2 = 2610, map = 1, name="The Proscenium"};
			{x1 = 3460, y1 = 2573, x2 = 3467, y2 = 2580, map = 1, name="Bakery"};
			{x1 = 3457, y1 = 2563, x2 = 3464, y2 = 2570, map = 1, name="The Bottled Imp"};
			{x1 = 3460, y1 = 2556, x2 = 3467, y2 = 2562, map = 1, name="Healers of New Haven"};
			{x1 = 3454, y1 = 2547, x2 = 3461, y2 = 2554, map = 1, name="Pressure Point"};
			{x1 = 3455, y1 = 2523, x2 = 3463, y2 = 2532, map = 1, name="Springs N Things"};
			{x1 = 3467, y1 = 2535, x2 = 3471, y2 = 2542, map = 1, name="Forge and Anvil"};
			{x1 = 3473, y1 = 2538, x2 = 3478, y2 = 2541, map = 1, name="Forge and Anvil"};
			{x1 = 3416, y1 = 2518, x2 = 3425, y2 = 2524, map = 1, name="Ninja's Dojo"};
			{x1 = 3419, y1 = 2514, x2 = 3424, y2 = 2517, map = 1, name="Ninja's Dojo"};
			{x1 = 3467, y1 = 2526, x2 = 3476, y2 = 2535, map = 1, name="Librium Arcanos"};
			{x1 = 3467, y1 = 2518, x2 = 3474, y2 = 2524, map = 1, name="Librium Arcanos"};
			{x1 = 3464, y1 = 2488, x2 = 3489, y2 = 2502, map = 1, name="New Haven Magery School"};
			{x1 = 3493, y1 = 2526, x2 = 3499, y2 = 2535, map = 1, name="Reagent Shop"};
			{x1 = 3492, y1 = 2546, x2 = 3503, y2 = 2556, map = 1, name="Finely Woven"};
			{x1 = 3505, y1 = 2546, x2 = 3510, y2 = 2555, map = 1, name="Bag of Many Things"};
			{x1 = 3518, y1 = 2510, x2 = 3542, y2 = 2551, map = 1, name="Haven Warriors Academy"};
			{x1 = 3520, y1 = 2552, x2 = 3535, y2 = 2563, map = 1, name="Haven Warriors Academy"};
	}
-------------------------------------------------------------------
KnownAreas["Old Haven"] = {}
KnownAreas["Old Haven"].MainAreas ={
			{x1 = 3589, y1 = 2443, x2 = 3704, y2 = 2544, map = 1, name="Old Haven"};
			{x1 = 3606, y1 = 2568, x2 = 3680, y2 = 2685, map = 1, name="New Player Quest Area"};
}
KnownAreas["Old Haven"].Guarded = false
KnownAreas["Old Haven"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Haven Misc Areas"] = {}
KnownAreas["Haven Misc Areas"].MainAreas ={
			{x1 = 3492, y1 = 2411, x2 = 3513, y2 = 2432, map = 1, name="Samurai Dojo"};
			{x1 = 3542, y1 = 2444, x2 = 3568, y2 = 2470, map = 1, name="Necromancer's School"};
}
KnownAreas["Haven Misc Areas"].Guarded = false
KnownAreas["Haven Misc Areas"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Moonglow"] = {}
KnownAreas["Moonglow"].MainAreas ={
			{x1 = 4535, y1 = 844, w = 20, h = 3, map = 0};
			{x1 = 4530, y1 = 847, w = 31, h = 61, map = 0};
			{x1 = 4521, y1 = 914, w = 56, h = 49, map = 0};
			{x1 = 4278, y1 = 915, w = 54, h = 19, map = 0};
			{x1 = 4283, y1 = 944, w = 53, h = 73, map = 0};
			{x1 = 4377, y1 = 1015, w = 59, h = 37, map = 0};
			{x1 = 4367, y1 = 1050, w = 142, h = 145, map = 0};
			{x1 = 4539, y1 = 1036, w = 27, h = 18, map = 0};
			{x1 = 4517, y1 = 1053, w = 23, h = 22, map = 0};
			{x1 = 4389, y1 = 1198, w = 47, h = 39, map = 0};
			{x1 = 4466, y1 = 1211, w = 32, h = 25, map = 0};
			{x1 = 4700, y1 = 1108, w = 17, h = 18, map = 0};
			{x1 = 4656, y1 = 1127, w = 26, h = 13, map = 0};
			{x1 = 4678, y1 = 1162, w = 25, h = 25, map = 0};
			{x1 = 4613, y1 = 1196, w = 23, h = 22, map = 0};
			{x1 = 4646, y1 = 1212, w = 14, h = 17, map = 0};
			{x1 = 4677, y1 = 1214, w = 26, h = 22, map = 0};
			{x1 = 4622, y1 = 1316, w = 22, h = 24, map = 0};
			{x1 = 4487, y1 = 1353, w = 59, h = 21, map = 0};
			{x1 = 4477, y1 = 1374, w = 69, h = 35, map = 0};
			{x1 = 4659, y1 = 1387, w = 40, h = 40, map = 0};
			{x1 = 4549, y1 = 1482, w = 29, h = 27, map = 0};
			{x1 = 4405, y1 = 1451, w = 23, h = 23, map = 0};
			{x1 = 4483, y1 = 1468, w = 21, h = 13, map = 0};
			
			{x1 = 4535, y1 = 844, w = 20, h = 3, map = 1};
			{x1 = 4530, y1 = 847, w = 31, h = 61, map = 1};
			{x1 = 4521, y1 = 914, w = 56, h = 49, map = 1};
			{x1 = 4278, y1 = 915, w = 54, h = 19, map = 1};
			{x1 = 4283, y1 = 944, w = 53, h = 73, map = 1};
			{x1 = 4377, y1 = 1015, w = 59, h = 37, map = 1};
			{x1 = 4367, y1 = 1050, w = 142, h = 145, map = 1};
			{x1 = 4539, y1 = 1036, w = 27, h = 18, map = 1};
			{x1 = 4517, y1 = 1053, w = 23, h = 22, map = 1};
			{x1 = 4389, y1 = 1198, w = 47, h = 39, map = 1};
			{x1 = 4466, y1 = 1211, w = 32, h = 25, map = 1};
			{x1 = 4700, y1 = 1108, w = 17, h = 18, map = 1};
			{x1 = 4656, y1 = 1127, w = 26, h = 13, map = 1};
			{x1 = 4678, y1 = 1162, w = 25, h = 25, map = 1};
			{x1 = 4613, y1 = 1196, w = 23, h = 22, map = 1};
			{x1 = 4646, y1 = 1212, w = 14, h = 17, map = 1};
			{x1 = 4677, y1 = 1214, w = 26, h = 22, map = 1};
			{x1 = 4622, y1 = 1316, w = 22, h = 24, map = 1};
			{x1 = 4487, y1 = 1353, w = 59, h = 21, map = 1};
			{x1 = 4477, y1 = 1374, w = 69, h = 35, map = 1};
			{x1 = 4659, y1 = 1387, w = 40, h = 40, map = 1};
			{x1 = 4549, y1 = 1482, w = 29, h = 27, map = 1};
			{x1 = 4405, y1 = 1451, w = 23, h = 23, map = 1};
			{x1 = 4483, y1 = 1468, w = 21, h = 13, map = 1};
}
KnownAreas["Moonglow"].Guarded = true
KnownAreas["Moonglow"].SubAreas = {}
	KnownAreas["Moonglow"].SubAreas["Tavern"] = {}
	KnownAreas["Moonglow"].SubAreas["Tavern"].Squares = {
			{x1 = 4384, y1 = 1152, w= 8, h=24, map = 0, name="The Scholar's Inn"};	
			{x1 = 4392, y1 = 1160, w= 16, h=8, map = 0, name="The Scholar's Inn"};	
			{x1 = 4400, y1 = 1152, w= 8, h=8, map = 0, name="The Scholar's Inn"};
			{x1 = 4480, y1 = 1056, w= 8, h=16, map = 0, name="The Student Hostel"};
			{x1 = 4488, y1 = 1060, w= 4, h=8, map = 0, name="The Student Hostel"};
			{x1 = 4476, y1 = 1060, w= 4, h=8, map = 0, name="The Student Hostel"};
			
			{x1 = 4384, y1 = 1152, w= 8, h=24, map = 1, name="The Scholar's Inn"};	
			{x1 = 4392, y1 = 1160, w= 16, h=8, map = 1, name="The Scholar's Inn"};	
			{x1 = 4400, y1 = 1152, w= 8, h=8, map = 1, name="The Scholar's Inn"};
			{x1 = 4480, y1 = 1056, w= 8, h=16, map = 1, name="The Student Hostel"};
			{x1 = 4488, y1 = 1060, w= 4, h=8, map = 1, name="The Student Hostel"};
			{x1 = 4476, y1 = 1060, w= 4, h=8, map = 1, name="The Student Hostel"};
	}
	KnownAreas["Moonglow"].SubAreas["Banks"] = {}
	KnownAreas["Moonglow"].SubAreas["Banks"].Squares = {
			{x1 = 4463, y1 = 1152, x2 = 4466, y2 = 1166, map = 0, name="First Bank of Moonglow and Tinkers Guild"};
			{x1 = 4467, y1 = 1156, x2 = 4475, y2 = 1166, map = 0, name="First Bank of Moonglow and Tinkers Guild"};
			{x1 = 4468, y1 = 1167, x2 = 4474, y2 = 1174, map = 0, name="First Bank of Moonglow and Tinkers Guild"};
			{x1 = 4475, y1 = 1152, x2 = 4479, y2 = 1166, map = 0, name="First Bank of Moonglow and Tinkers Guild"};
			
			{x1 = 4463, y1 = 1152, x2 = 4466, y2 = 1166, map = 1, name="First Bank of Moonglow and Tinkers Guild"};
			{x1 = 4467, y1 = 1156, x2 = 4475, y2 = 1166, map = 1, name="First Bank of Moonglow and Tinkers Guild"};
			{x1 = 4468, y1 = 1167, x2 = 4474, y2 = 1174, map = 1, name="First Bank of Moonglow and Tinkers Guild"};
			{x1 = 4475, y1 = 1152, x2 = 4479, y2 = 1166, map = 1, name="First Bank of Moonglow and Tinkers Guild"};
	}
	KnownAreas["Moonglow"].SubAreas["Shops"] = {}
	KnownAreas["Moonglow"].SubAreas["Shops"].Squares = {
			{x1 = 4436, y1 = 1152, x2 = 4442, y2 = 1159, map = 0, name="Second Defense Armory"};
			{x1 = 4432, y1 = 1160, x2 = 4446, y2 = 1166, map = 0, name="Second Defense Armory"};
			{x1 = 4384, y1 = 1130, x2 = 4391, y2 = 1136, map = 0, name="The Fatted Calf"};
			{x1 = 4392, y1 = 1130, x2 = 4398, y2 = 1144, map = 0, name="The Fatted Calf"};
			{x1 = 4408, y1 = 1128, x2 = 4414, y2 = 1142, map = 0, name="Herbal Splendor"};
			{x1 = 4415, y1 = 1128, x2 = 4422, y2 = 1134, map = 0, name="Herbal Splendor"};
			{x1 = 4384, y1 = 1104, x2 = 4390, y2 = 1111, map = 0, name="The Mighty Axe"};
			{x1 = 4384, y1 = 1112, x2 = 4398, y2 = 1118, map = 0, name="The Mighty Axe"};
			{x1 = 4408, y1 = 1108, x2 = 4422, y2 = 1114, map = 0, name="Aegis' Reagent Shop"};
			{x1 = 4408, y1 = 1080, x2 = 4422, y2 = 1094, map = 0, name="The Mage's Seat"};
			{x1 = 4384, y1 = 1080, x2 = 4398, y2 = 1086, map = 0, name="Moonglow Healer"};
			{x1 = 4384, y1 = 1086, x2 = 4390, y2 = 1094, map = 0, name="Moonglow Healer"};
			{x1 = 4384, y1 = 1056, x2 = 4390, y2 = 1063, map = 0, name="Mage's Bread"};
			{x1 = 4384, y1 = 1064, x2 = 4395, y2 = 1070, map = 0, name="Mage's Bread"};
			{x1 = 4408, y1 = 1057, x2 = 4414, y2 = 1059, map = 0, name="The Scholar's Goods"};
			{x1 = 4408, y1 = 1061, x2 = 4422, y2 = 1066, map = 0, name="The Scholar's Goods"};
			{x1 = 4448, y1 = 1056, x2 = 4462, y2 = 1070, map = 0, name="Scholars Cut"};
			{x1 = 4447, y1 = 1086, x2 = 4450, y2 = 1093, map = 0, name="Moonglow's Finest Alchemy"};
			{x1 = 4460, y1 = 1087, x2 = 4463, y2 = 1094, map = 0, name="Moonglow's Finest Alchemy"};
			{x1 = 4447, y1 = 1080, x2 = 4463, y2 = 1086, map = 0, name="Moonglow's Finest Alchemy"};
			{x1 = 4473, y1 = 1080, x2 = 4486, y2 = 1086, map = 0, name="Farmer's Market"};
			{x1 = 4476, y1 = 1087, x2 = 4482, y2 = 1090, map = 0, name="Farmer's Market"};
			{x1 = 4468, y1 = 1118, x2 = 4474, y2 = 1132, map = 0, name="Councilor's Guild"};
			{x1 = 4476, y1 = 1122, x2 = 4482, y2 = 1128, map = 0, name="Councilor's Guild"};
			{x1 = 4484, y1 = 1118, x2 = 4490, y2 = 1132, map = 0, name="Councilor's Guild"};
			{x1 = 4520, y1 = 1056, x2 = 4526, y2 = 1070, map = 0, name="Moonglow Academy of Arts"};
			{x1 = 4534, y1 = 856, x2 = 4556, y2 = 862, map = 0, name="Encyclopedia Magika"};
			{x1 = 4542, y1 = 848, x2 = 4548, y2 = 870, map = 0, name="Encyclopedia Magika"};
			{x1 = 4616, y1 = 1200, x2 = 4630, y2 = 1206, map = 0, name="Illusionist's Guild"};
			{x1 = 4624, y1 = 1207, x2 = 4630, y2 = 1214, map = 0, name="Illusionist's Guild"};
			{x1 = 4704, y1 = 1112, x2 = 4713, y2 = 1121, map = 0, name="Telescope"};
			{x1 = 4672, y1 = 1407, x2 = 4694, y2 = 1413, map = 0, name="Sorcer's Guild"};
			{x1 = 4680, y1 = 1414, x2 = 4686, y2 = 1421, map = 0, name="Sorcer's Guild"};
			{x1 = 4552, y1 = 1488, x2 = 4558, y2 = 1502, map = 0, name="Farm"};
			{x1 = 4560, y1 = 1488, x2 = 4566, y2 = 1494, map = 0, name="Farm"};
			{x1 = 4408, y1 = 1456, x2 = 4414, y2 = 1470, map = 0, name="Farm"};
			{x1 = 4416, y1 = 1461, x2 = 4422, y2 = 1466, map = 0, name="Farm"};
			{x1 = 4486, y1 = 1353, x2 = 4535, y2 = 1375, map = 0, name="Britannia Royal Zoo"};
			{x1 = 4478, y1 = 1375, x2 = 4523, y2 = 1399, map = 0, name="Britannia Royal Zoo"};
			{x1 = 4521, y1 = 1376, x2 = 4537, y2 = 1392, map = 0, name="Britannia Royal Zoo"};
			{x1 = 4286, y1 = 948, x2 = 4334, y2 = 1010, map = 0, name="The Lycaeum"};
	
			{x1 = 4436, y1 = 1152, x2 = 4442, y2 = 1159, map = 1, name="Second Defense Armory"};
			{x1 = 4432, y1 = 1160, x2 = 4446, y2 = 1166, map = 1, name="Second Defense Armory"};
			{x1 = 4384, y1 = 1130, x2 = 4391, y2 = 1136, map = 1, name="The Fatted Calf"};
			{x1 = 4392, y1 = 1130, x2 = 4398, y2 = 1144, map = 1, name="The Fatted Calf"};
			{x1 = 4408, y1 = 1128, x2 = 4414, y2 = 1142, map = 1, name="Herbal Splendor"};
			{x1 = 4415, y1 = 1128, x2 = 4422, y2 = 1134, map = 1, name="Herbal Splendor"};
			{x1 = 4384, y1 = 1104, x2 = 4390, y2 = 1111, map = 1, name="The Mighty Axe"};
			{x1 = 4384, y1 = 1112, x2 = 4398, y2 = 1118, map = 1, name="The Mighty Axe"};
			{x1 = 4408, y1 = 1108, x2 = 4422, y2 = 1114, map = 1, name="Aegis' Reagent Shop"};
			{x1 = 4408, y1 = 1080, x2 = 4422, y2 = 1094, map = 1, name="The Mage's Seat"};
			{x1 = 4384, y1 = 1080, x2 = 4398, y2 = 1086, map = 1, name="Moonglow Healer"};
			{x1 = 4384, y1 = 1086, x2 = 4390, y2 = 1094, map = 1, name="Moonglow Healer"};
			{x1 = 4384, y1 = 1056, x2 = 4390, y2 = 1063, map = 1, name="Mage's Bread"};
			{x1 = 4384, y1 = 1064, x2 = 4395, y2 = 1070, map = 1, name="Mage's Bread"};
			{x1 = 4408, y1 = 1057, x2 = 4414, y2 = 1059, map = 1, name="The Scholar's Goods"};
			{x1 = 4408, y1 = 1061, x2 = 4422, y2 = 1066, map = 1, name="The Scholar's Goods"};
			{x1 = 4448, y1 = 1056, x2 = 4462, y2 = 1070, map = 1, name="Scholars Cut"};
			{x1 = 4447, y1 = 1086, x2 = 4450, y2 = 1093, map = 1, name="Moonglow's Finest Alchemy"};
			{x1 = 4460, y1 = 1087, x2 = 4463, y2 = 1094, map = 1, name="Moonglow's Finest Alchemy"};
			{x1 = 4447, y1 = 1080, x2 = 4463, y2 = 1086, map = 1, name="Moonglow's Finest Alchemy"};
			{x1 = 4473, y1 = 1080, x2 = 4486, y2 = 1086, map = 1, name="Farmer's Market"};
			{x1 = 4476, y1 = 1087, x2 = 4482, y2 = 1090, map = 1, name="Farmer's Market"};
			{x1 = 4468, y1 = 1118, x2 = 4474, y2 = 1132, map = 1, name="Councilor's Guild"};
			{x1 = 4476, y1 = 1122, x2 = 4482, y2 = 1128, map = 1, name="Councilor's Guild"};
			{x1 = 4484, y1 = 1118, x2 = 4490, y2 = 1132, map = 1, name="Councilor's Guild"};
			{x1 = 4520, y1 = 1056, x2 = 4526, y2 = 1070, map = 1, name="Moonglow Academy of Arts"};
			{x1 = 4534, y1 = 856, x2 = 4556, y2 = 862, map = 1, name="Encyclopedia Magika"};
			{x1 = 4542, y1 = 848, x2 = 4548, y2 = 870, map = 1, name="Encyclopedia Magika"};
			{x1 = 4616, y1 = 1200, x2 = 4630, y2 = 1206, map = 1, name="Illusionist's Guild"};
			{x1 = 4624, y1 = 1207, x2 = 4630, y2 = 1214, map = 1, name="Illusionist's Guild"};
			{x1 = 4704, y1 = 1112, x2 = 4713, y2 = 1121, map = 1, name="Telescope"};
			{x1 = 4672, y1 = 1407, x2 = 4694, y2 = 1413, map = 1, name="Sorcer's Guild"};
			{x1 = 4680, y1 = 1414, x2 = 4686, y2 = 1421, map = 1, name="Sorcer's Guild"};
			{x1 = 4552, y1 = 1488, x2 = 4558, y2 = 1502, map = 1, name="Farm"};
			{x1 = 4560, y1 = 1488, x2 = 4566, y2 = 1494, map = 1, name="Farm"};
			{x1 = 4408, y1 = 1456, x2 = 4414, y2 = 1470, map = 1, name="Farm"};
			{x1 = 4416, y1 = 1461, x2 = 4422, y2 = 1466, map = 1, name="Farm"};
			{x1 = 4486, y1 = 1353, x2 = 4535, y2 = 1375, map = 1, name="Britannia Royal Zoo"};
			{x1 = 4478, y1 = 1375, x2 = 4523, y2 = 1399, map = 1, name="Britannia Royal Zoo"};
			{x1 = 4521, y1 = 1376, x2 = 4537, y2 = 1392, map = 1, name="Britannia Royal Zoo"};
			{x1 = 4286, y1 = 948, x2 = 4334, y2 = 1010, map = 1, name="The Lycaeum"};
	}
-------------------------------------------------------------------
KnownAreas["Britain"] = {}
KnownAreas["Britain"].MainAreas ={
			{x1 = 1416, y1 = 1498, w = 324, h = 279, map = 0};
			{x1 = 1500, y1 = 1408, w = 46, h = 90, map = 0 };
			{x1 = 1385, y1 = 1538, w = 31, h = 239, map = 0 };
			{x1 = 1416, y1 = 1777, w = 324, h = 60, map = 0 };
			{x1 = 1385, y1 = 1777, w = 31, h = 130, map = 0 };
			{x1 = 1093, y1 = 1538, w = 292, h = 369, map = 0 };
			
			{x1 = 1416, y1 = 1498, w = 324, h = 279, map = 1};
			{x1 = 1500, y1 = 1408, w = 46, h = 90, map = 1 };
			{x1 = 1385, y1 = 1538, w = 31, h = 239, map = 1 };
			{x1 = 1416, y1 = 1777, w = 324, h = 60, map = 1 };
			{x1 = 1385, y1 = 1777, w = 31, h = 130, map = 1 };
			{x1 = 1093, y1 = 1538, w = 292, h = 369, map = 1 };
}
KnownAreas["Britain"].Guarded = true
KnownAreas["Britain"].SubAreas = {}
	KnownAreas["Britain"].SubAreas["Tavern"] = {}
	KnownAreas["Britain"].SubAreas["Tavern"].Squares = {
			{x1 = 1492, y1 = 1602, w = 8, h = 19, map = 0, name="Sweet Dreams" };
			{x1 = 1500, y1 = 1610, w = 8, h = 16, map = 0, name="Sweet Dreams" };
			{x1 = 1576, y1 = 1584, w = 24, h = 16, map = 0, name="The Wayfarer's Inn" };
			{x1 = 1456, y1 = 1512, w = 16, h = 16, map = 0, name="The North side Inn" };
			{x1 = 1472, y1 = 1512, w = 8, h = 8, map = 0, name="The North side Inn" };
			{x1 = 1486, y1 = 1684, w = 8, h = 8, map = 0, name="The Blue Boar" };
			{x1 = 1494, y1 = 1676, w = 8, h = 24, map = 0, name="The Blue Boar" };
			{x1 = 1424, y1 = 1712, w = 7, h = 23, map = 0, name="The Cat's Lair" };
			{x1 = 1432, y1 = 1712, w = 7, h = 11, map = 0, name="The Cat's Lair"  };
			{x1 = 1608, y1 = 1584, w = 24, h = 8, map = 0, name="The Salty Dog" };
			{x1 = 1616, y1 = 1576, w = 8, h = 8, map = 0, name="The Salty Dog" };
			{x1 = 1544, y1 = 1760, w = 16, h = 16, map = 0, name="The Unicorn's Horn" };
			{x1 = 1560, y1 = 1760, w = 8, h = 8, map = 0, name="The Unicorn's Horn" };
	
			{x1 = 1492, y1 = 1602, w = 8, h = 19, map = 1, name="Sweet Dreams" };
			{x1 = 1500, y1 = 1610, w = 8, h = 16, map = 1, name="Sweet Dreams" };
			{x1 = 1576, y1 = 1584, w = 24, h = 16, map = 1, name="The Wayfarer's Inn" };
			{x1 = 1456, y1 = 1512, w = 16, h = 16, map = 1, name="The North side Inn" };
			{x1 = 1472, y1 = 1512, w = 8, h = 8, map = 1, name="The North side Inn" };
			{x1 = 1486, y1 = 1684, w = 8, h = 8, map = 1, name="The Blue Boar" };
			{x1 = 1494, y1 = 1676, w = 8, h = 24, map = 1, name="The Blue Boar" };
			{x1 = 1424, y1 = 1712, w = 7, h = 23, map = 1, name="The Cat's Lair" };
			{x1 = 1432, y1 = 1712, w = 7, h = 11, map = 1, name="The Cat's Lair"  };
			{x1 = 1608, y1 = 1584, w = 24, h = 8, map = 1, name="The Salty Dog" };
			{x1 = 1616, y1 = 1576, w = 8, h = 8, map = 1, name="The Salty Dog" };
			{x1 = 1544, y1 = 1760, w = 16, h = 16, map = 1, name="The Unicorn's Horn" };
			{x1 = 1560, y1 = 1760, w = 8, h = 8, map = 1, name="The Unicorn's Horn" };
	}
	KnownAreas["Britain"].SubAreas["Banks"] = {}
	KnownAreas["Britain"].SubAreas["Banks"].Squares = {
			{x1 = 1424, y1 = 1675, x2 = 1430, y2 = 1691, map = 0, name="The First Bank of Britain"};
			{x1 = 1431, y1 = 1683, x2 = 1440, y2 = 1691, map = 0, name="The First Bank of Britain"};
			{x1 = 1648, y1 = 1600, x2 = 1654, y2 = 1614, map = 0, name="The East Side Bank"};
			{x1 = 1656, y1 = 1600, x2 = 1662, y2 = 1606, map = 0, name="The East Side Bank"};
			
			{x1 = 1424, y1 = 1675, x2 = 1430, y2 = 1691, map = 1, name="The First Bank of Britain"};
			{x1 = 1431, y1 = 1683, x2 = 1440, y2 = 1691, map = 1, name="The First Bank of Britain"};
			{x1 = 1648, y1 = 1600, x2 = 1654, y2 = 1614, map = 1, name="The East Side Bank"};
			{x1 = 1656, y1 = 1600, x2 = 1662, y2 = 1606, map = 1, name="The East Side Bank"};
	}
	KnownAreas["Britain"].SubAreas["Faction Stronghold"] = {}
	KnownAreas["Britain"].SubAreas["Faction Stronghold"].Squares = {
			{x1 = 1296, y1 = 1560, x2 = 1406, y2 = 1694, map = 0, name="True Britannians Stronghold"};
	}
	KnownAreas["Britain"].SubAreas["Castle Britannia"] = {}
	KnownAreas["Britain"].SubAreas["Castle Britannia"].Squares = {
			{x1 = 1296, y1 = 1560, x2 = 1406, y2 = 1694, map = 1};
	}
	KnownAreas["Britain"].SubAreas["Castle Blackthorn"] = {}
	KnownAreas["Britain"].SubAreas["Castle Blackthorn"].Squares = {
			{x1 = 1512, y1 = 1422, x2 = 1537, y2 = 1438, map = 0, name="Castle Blackthorn"};
			{x1 = 1522, y1 = 1412, x2 = 1537, y2 = 1420, map = 0, name="Castle Blackthorn"};
			{x1 = 1505, y1 = 1441, x2 = 1536, y2 = 1461, map = 0, name="Castle Blackthorn"};
			
			{x1 = 1512, y1 = 1422, x2 = 1537, y2 = 1438, map = 1, name="Castle Blackthorn"};
			{x1 = 1522, y1 = 1412, x2 = 1537, y2 = 1420, map = 1, name="Castle Blackthorn"};
			{x1 = 1505, y1 = 1441, x2 = 1536, y2 = 1461, map = 1, name="Castle Blackthorn"};
	}	
	KnownAreas["Britain"].SubAreas["Shops"] = {}
	KnownAreas["Britain"].SubAreas["Shops"].Squares = {
			{x1 = 1256, y1 = 1880, x2 = 1262, y2 = 1894, map = 0, name="Farm"};		
			{x1 = 1192, y1 = 1848, x2 = 1206, y2 = 1854, map = 0, name="Farm"};	
			{x1 = 1128, y1 = 1816, x2 = 1142, y2 = 1822, map = 0, name="Farm"};
			{x1 = 1184, y1 = 1704, x2 = 1198, y2 = 1718, map = 0, name="Farm"};
			{x1 = 1240, y1 = 1696, x2 = 1246, y2 = 1702, map = 0, name="Farm"};
			{x1 = 1248, y1 = 1696, x2 = 1254, y2 = 1710, map = 0, name="Farm"};
			{x1 = 1144, y1 = 1616, x2 = 1158, y2 = 1622, map = 0, name="Farm"};
			{x1 = 1144, y1 = 1544, x2 = 1158, y2 = 1550, map = 0, name="Farm"};
			{x1 = 1224, y1 = 1568, x2 = 1230, y2 = 1582, map = 0, name="Farm"};
			{x1 = 1231, y1 = 1568, x2 = 1238, y2 = 1574, map = 0, name="Farm"};
			{x1 = 1288, y1 = 1752, x2 = 1306, y2 = 1782, map = 0, name="Sosarian Steeds"};
			{x1 = 1332, y1 = 1724, x2 = 1354, y2 = 1746, map = 0, name="Warrior's Guild"};
			{x1 = 1344, y1 = 1768, x2 = 1358, y2 = 1788, map = 0, name="Britain's Blcksmith Guild"};
			{x1 = 1412, y1 = 1744, x2 = 1422, y2 = 1758, map = 0, name="The Oaken Oar"};
			{x1 = 1424, y1 = 1752, x2 = 1430, y2 = 1758, map = 0, name="The Oaken Oar"};
			{x1 = 1448, y1 = 1720, x2 = 1462, y2 = 1726, map = 0, name="The Cleaver"};
			{x1 = 1422, y1 = 1647, x2 = 1430, y2 = 1664, map = 0, name="The Tinker's Guild"};
			{x1 = 1436, y1 = 1646, x2 = 1450, y2 = 1652, map = 0, name="Heavy Metal Armorer"};
			{x1 = 1440, y1 = 1660, x2 = 1453, y2 = 1668, map = 0, name="Artist's Guild"};
			{x1 = 1450, y1 = 1678, x2 = 1456, y2 = 1692, map = 0, name="Premier Gems"};
			{x1 = 1465, y1 = 1664, x2 = 1486, y2 = 1674, map = 0, name="Britain's Premier Provisioners and Fish Shoppe"};
			{x1 = 1466, y1 = 1684, x2 = 1472, y2 = 1694, map = 0, name="The Lord's Clothiers"};
			{x1 = 1472, y1 = 1684, x2 = 1476, y2 = 1690, map = 0, name="The Lord's Clothiers"};
			{x1 = 1492, y1 = 1713, x2 = 1498, y2 = 1722, map = 0, name="The First Library of Britain"};
			{x1 = 1472, y1 = 1736, x2 = 1478, y2 = 1750, map = 0, name="Customs"};
			{x1 = 1479, y1 = 1736, x2 = 1482, y2 = 1742, map = 0, name="Customs"};
			{x1 = 1496, y1 = 1656, x2 = 1506, y2 = 1662, map = 0, name="Ethereal Goods"};
			{x1 = 1496, y1 = 1663, x2 = 1502, y2 = 1666, map = 0, name="Ethereal Goods"};
			{x1 = 1648, y1 = 1632, x2 = 1662, y2 = 1646, map = 0, name="A Girl's Best Friend"};
			{x1 = 1648, y1 = 1647, x2 = 1654, y2 = 1654, map = 0, name="A Girl's Best Friend"};
			{x1 = 1624, y1 = 1656, x2 = 1638, y2 = 1670, map = 0, name="Counselor's Guild"};
			{x1 = 1632, y1 = 1688, x2 = 1638, y2 = 1710, map = 0, name="Artistic Armor"};
			{x1 = 1640, y1 = 1696, x2 = 1646, y2 = 1702, map = 0, name="Artistic Armor"};
			{x1 = 1616, y1 = 1760, x2 = 1622, y2 = 1766, map = 0, name="The Watch Tower"};
			{x1 = 1600, y1 = 1704, x2 = 1606, y2 = 1718, map = 0, name="Profuse Provisions"};
			{x1 = 1607, y1 = 1704, x2 = 1614, y2 = 1710, map = 0, name="Profuse Provisions"};
			{x1 = 1584, y1 = 1648, x2 = 1598, y2 = 1662, map = 0, name="Incantations & Enchantments"};
			{x1 = 1600, y1 = 1648, x2 = 1606, y2 = 1654, map = 0, name="Incantations & Enchantments"};
			{x1 = 1544, y1 = 1656, x2 = 1566, y2 = 1662, map = 0, name="The Right Fit"};
			{x1 = 1560, y1 = 1648, x2 = 1566, y2 = 1656, map = 0, name="The Right Fit"};
			{x1 = 1544, y1 = 1648, x2 = 1550, y2 = 1654, map = 0, name="The Right Fit"};
			{x1 = 1468, y1 = 1608, x2 = 1478, y2 = 1614, map = 0, name="Healer of Britain"};
			{x1 = 1448, y1 = 1608, x2 = 1454, y2 = 1618, map = 0, name="Good Eats"};
			{x1 = 1454, y1 = 1608, x2 = 1458, y2 = 1614, map = 0, name="Good Eats"};
			{x1 = 1428, y1 = 1608, x2 = 1438, y2 = 1614, map = 0, name="The Best Hides of Britain"};
			{x1 = 1428, y1 = 1592, x2 = 1438, y2 = 1598, map = 0, name="The Saw Horse"};
			{x1 = 1448, y1 = 1576, x2 = 1458, y2 = 1598, map = 0, name="The King's Men Theater"};
			{x1 = 1441, y1 = 1576, x2 = 1446, y2 = 1582, map = 0, name="The King's Men Theater"};
			{x1 = 1468, y1 = 1592, x2 = 1482, y2 = 1598, map = 0, name="Merchant's Guild"};
			{x1 = 1480, y1 = 1580, x2 = 1486, y2 = 1589, map = 0, name="Strength and Steel"};
			{x1 = 1469, y1 = 1576, x2 = 1477, y2 = 1582, map = 0, name="Quality Fletching"};
			{x1 = 1484, y1 = 1544, x2 = 1498, y2 = 1558, map = 0, name="The Sorcerer's Delight: Shop, Library, & Guild"};
			{x1 = 1504, y1 = 1564, x2 = 1514, y2 = 1574, map = 0, name="Britannia Animal Care"};
			{x1 = 1509, y1 = 1560, x2 = 1512, y2 = 1563, map = 0, name="Britannia Animal Care"};
			{x1 = 1508, y1 = 1540, x2 = 1526, y2 = 1550, map = 0, name="The Bucking Horse Stables"};
			{x1 = 1496, y1 = 1512, x2 = 1510, y2 = 1526, map = 0, name="Counselor's Guild"};
			{x1 = 1436, y1 = 1548, x2 = 1474, y2 = 1566, map = 0, name="Lord British's Conservatory of Music"};
			{x1 = 1416, y1 = 1544, x2 = 1426, y2 = 1550, map = 0, name="The Hammer and Anvil"};
			{x1 = 1416, y1 = 1552, x2 = 1420, y2 = 1558, map = 0, name="The Hammer and Anvil"};
			{x1 = 1408, y1 = 1588, x2 = 1418, y2 = 1610, map = 0, name="Britain Public Library"};
			{x1 = 1416, y1 = 1576, x2 = 1430, y2 = 1582, map = 0, name="Miner's Guild"};
			
			{x1 = 1256, y1 = 1880, x2 = 1262, y2 = 1894, map = 1, name="Farm"};		
			{x1 = 1192, y1 = 1848, x2 = 1206, y2 = 1854, map = 1, name="Farm"};	
			{x1 = 1128, y1 = 1816, x2 = 1142, y2 = 1822, map = 1, name="Farm"};
			{x1 = 1184, y1 = 1704, x2 = 1198, y2 = 1718, map = 1, name="Farm"};
			{x1 = 1240, y1 = 1696, x2 = 1246, y2 = 1702, map = 1, name="Farm"};
			{x1 = 1248, y1 = 1696, x2 = 1254, y2 = 1710, map = 1, name="Farm"};
			{x1 = 1144, y1 = 1616, x2 = 1158, y2 = 1622, map = 1, name="Farm"};
			{x1 = 1144, y1 = 1544, x2 = 1158, y2 = 1550, map = 1, name="Farm"};
			{x1 = 1224, y1 = 1568, x2 = 1230, y2 = 1582, map = 1, name="Farm"};
			{x1 = 1231, y1 = 1568, x2 = 1238, y2 = 1574, map = 1, name="Farm"};
			{x1 = 1288, y1 = 1752, x2 = 1306, y2 = 1782, map = 1, name="Sosarian Steeds"};
			{x1 = 1332, y1 = 1724, x2 = 1354, y2 = 1746, map = 1, name="Warrior's Guild"};
			{x1 = 1344, y1 = 1768, x2 = 1358, y2 = 1788, map = 1, name="Britain's Blcksmith Guild"};
			{x1 = 1412, y1 = 1744, x2 = 1422, y2 = 1758, map = 1, name="The Oaken Oar"};
			{x1 = 1424, y1 = 1752, x2 = 1430, y2 = 1758, map = 1, name="The Oaken Oar"};
			{x1 = 1448, y1 = 1720, x2 = 1462, y2 = 1726, map = 1, name="The Cleaver"};
			{x1 = 1422, y1 = 1647, x2 = 1430, y2 = 1664, map = 1, name="The Tinker's Guild"};
			{x1 = 1436, y1 = 1646, x2 = 1450, y2 = 1652, map = 1, name="Heavy Metal Armorer"};
			{x1 = 1440, y1 = 1660, x2 = 1453, y2 = 1668, map = 1, name="Artist's Guild"};
			{x1 = 1450, y1 = 1678, x2 = 1456, y2 = 1692, map = 1, name="Premier Gems"};
			{x1 = 1465, y1 = 1664, x2 = 1486, y2 = 1674, map = 1, name="Britain's Premier Provisioners and Fish Shoppe"};
			{x1 = 1466, y1 = 1684, x2 = 1472, y2 = 1694, map = 1, name="The Lord's Clothiers"};
			{x1 = 1472, y1 = 1684, x2 = 1476, y2 = 1690, map = 1, name="The Lord's Clothiers"};
			{x1 = 1492, y1 = 1713, x2 = 1498, y2 = 1722, map = 1, name="The First Library of Britain"};
			{x1 = 1472, y1 = 1736, x2 = 1478, y2 = 1750, map = 1, name="Customs"};
			{x1 = 1479, y1 = 1736, x2 = 1482, y2 = 1742, map = 1, name="Customs"};
			{x1 = 1496, y1 = 1656, x2 = 1506, y2 = 1662, map = 1, name="Ethereal Goods"};
			{x1 = 1496, y1 = 1663, x2 = 1502, y2 = 1666, map = 1, name="Ethereal Goods"};
			{x1 = 1648, y1 = 1632, x2 = 1662, y2 = 1646, map = 1, name="A Girl's Best Friend"};
			{x1 = 1648, y1 = 1647, x2 = 1654, y2 = 1654, map = 1, name="A Girl's Best Friend"};
			{x1 = 1624, y1 = 1656, x2 = 1638, y2 = 1670, map = 1, name="Counselor's Guild"};
			{x1 = 1632, y1 = 1688, x2 = 1638, y2 = 1710, map = 1, name="Artistic Armor"};
			{x1 = 1640, y1 = 1696, x2 = 1646, y2 = 1702, map = 1, name="Artistic Armor"};
			{x1 = 1616, y1 = 1760, x2 = 1622, y2 = 1766, map = 1, name="The Watch Tower"};
			{x1 = 1600, y1 = 1704, x2 = 1606, y2 = 1718, map = 1, name="Profuse Provisions"};
			{x1 = 1607, y1 = 1704, x2 = 1614, y2 = 1710, map = 1, name="Profuse Provisions"};
			{x1 = 1584, y1 = 1648, x2 = 1598, y2 = 1662, map = 1, name="Incantations & Enchantments"};
			{x1 = 1600, y1 = 1648, x2 = 1606, y2 = 1654, map = 1, name="Incantations & Enchantments"};
			{x1 = 1544, y1 = 1656, x2 = 1566, y2 = 1662, map = 1, name="The Right Fit"};
			{x1 = 1560, y1 = 1648, x2 = 1566, y2 = 1656, map = 1, name="The Right Fit"};
			{x1 = 1544, y1 = 1648, x2 = 1550, y2 = 1654, map = 1, name="The Right Fit"};
			{x1 = 1468, y1 = 1608, x2 = 1478, y2 = 1614, map = 1, name="Healer of Britain"};
			{x1 = 1448, y1 = 1608, x2 = 1454, y2 = 1618, map = 1, name="Good Eats"};
			{x1 = 1454, y1 = 1608, x2 = 1458, y2 = 1614, map = 1, name="Good Eats"};
			{x1 = 1428, y1 = 1608, x2 = 1438, y2 = 1614, map = 1, name="The Best Hides of Britain"};
			{x1 = 1428, y1 = 1592, x2 = 1438, y2 = 1598, map = 1, name="The Saw Horse"};
			{x1 = 1448, y1 = 1576, x2 = 1458, y2 = 1598, map = 1, name="The King's Men Theater"};
			{x1 = 1441, y1 = 1576, x2 = 1446, y2 = 1582, map = 1, name="The King's Men Theater"};
			{x1 = 1468, y1 = 1592, x2 = 1482, y2 = 1598, map = 1, name="Merchant's Guild"};
			{x1 = 1480, y1 = 1580, x2 = 1486, y2 = 1589, map = 1, name="Strength and Steel"};
			{x1 = 1469, y1 = 1576, x2 = 1477, y2 = 1582, map = 1, name="Quality Fletching"};
			{x1 = 1484, y1 = 1544, x2 = 1498, y2 = 1558, map = 1, name="The Sorcerer's Delight: Shop, Library, & Guild"};
			{x1 = 1504, y1 = 1564, x2 = 1514, y2 = 1574, map = 1, name="Britannia Animal Care"};
			{x1 = 1509, y1 = 1560, x2 = 1512, y2 = 1563, map = 1, name="Britannia Animal Care"};
			{x1 = 1508, y1 = 1540, x2 = 1526, y2 = 1550, map = 1, name="The Bucking Horse Stables"};
			{x1 = 1496, y1 = 1512, x2 = 1510, y2 = 1526, map = 1, name="Counselor's Guild"};
			{x1 = 1436, y1 = 1548, x2 = 1474, y2 = 1566, map = 1, name="Lord British's Conservatory of Music"};
			{x1 = 1416, y1 = 1544, x2 = 1426, y2 = 1550, map = 1, name="The Hammer and Anvil"};
			{x1 = 1416, y1 = 1552, x2 = 1420, y2 = 1558, map = 1, name="The Hammer and Anvil"};
			{x1 = 1408, y1 = 1588, x2 = 1418, y2 = 1610, map = 1, name="Britain Public Library"};
			{x1 = 1360, y1 = 1572, x2 = 1374, y2 = 1578, map = 1, name="The Lord's Arms"};
			{x1 = 1368, y1 = 1579, x2 = 1374, y2 = 1582, map = 1, name="The Lord's Arms"};
			{x1 = 1384, y1 = 1641, x2 = 1392, y2 = 1662, map = 1, name="Stables"};
			{x1 = 1384, y1 = 1595, x2 = 1394, y2 = 1606, map = 1, name="Lord British' Tailor"};
			{x1 = 1416, y1 = 1576, x2 = 1430, y2 = 1582, map = 1, name="Miner's Guild"};
	}
-------------------------------------------------------------------
KnownAreas["Faction Strongholds"] = {}
KnownAreas["Faction Strongholds"].MainAreas ={
			{x1 = 1110, y1 = 2582, w = 51, h = 30, map = 0, name="Minax Stronghold"};
			{x1 = 4448, y1 = 1491, w = 38, h = 80, map = 0, name="Council of Mages Stronghold"};

			{x1 = 960, y1 = 752, x2 = 974, y2 = 762, map = 0, name="Shadowlords Stronghold"};
			{x1 = 960, y1 = 688, x2 = 966, y2 = 762, z = -20, map = 0, name="Shadowlords Stronghold"};
			{x1 = 958, y1 = 704, x2 = 968, y2 = 734, z = -40, map = 0, name="Shadowlords Stronghold"};
			{x1 = 969, y1 = 724, x2 = 992, y2 = 727, z = -40, map = 0, name="Shadowlords Stronghold"};
			{x1 = 960, y1 = 688, x2 = 966, y2 = 718, map = 0, name="Shadowlords Stronghold"};
			{x1 = 944, y1 = 697, x2 = 966, y2 = 718, map = 0, name="Shadowlords Stronghold"};
			{x1 = 994, y1 = 720, x2 = 1000, y2 = 726, z = -40, map = 0, name="Shadowlords Stronghold"};
			{x1 = 994, y1 = 712, x2 = 1000, y2 = 718, z = -20, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1001, y1 = 713, x2 = 1022, y2 = 715, z = -20, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1014, y1 = 717, x2 = 1022, y2 = 739, z = -40, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1016, y1 = 741, x2 = 1019, y2 = 777, z = -40, map = 0, name="Shadowlords Stronghold"};
			{x1 = 998, y1 = 757, x2 = 1019, y2 = 777, z = -40, map = 0, name="Shadowlords Stronghold"};
			{x1 = 998, y1 = 757, x2 = 1019, y2 = 777, z = -55, map = 0, name="Shadowlords Stronghold"};
			{x1 = 998, y1 = 757, x2 = 1019, y2 = 777, z = -60, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1014, y1 = 778, x2 = 1020, y2 = 788, z = -40, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1006, y1 = 786, x2 = 1012, y2 = 796, z = -20, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1006, y1 = 796, x2 = 1012, y2 = 824, z = -20, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1006, y1 = 818, x2 = 1012, y2 = 824, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1014, y1 = 818, x2 = 1020, y2 = 830, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1013, y1 = 787, x2 = 1020, y2 = 788, z = -20, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1016, y1 = 787, x2 = 1018, y2 = 788, z = -33, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1012, y1 = 693, x2 = 1022, y2 = 721, z = -20, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1012, y1 = 693, x2 = 1022, y2 = 721, z = -33, map = 0, name="Shadowlords Stronghold"};
			{x1 = 1012, y1 = 693, x2 = 1018, y2 = 710, map = 0, name="Shadowlords Stronghold"};
			{x1 = 994, y1 = 719, x2 = 1000, y2 = 721, z = -33, map = 0, name="Shadowlords Stronghold"};
			{x1 = 994, y1 = 719, x2 = 1000, y2 = 721, z = -20, map = 0, name="Shadowlords Stronghold"};
}
KnownAreas["Faction Strongholds"].Guarded = false
KnownAreas["Faction Strongholds"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Cove"] = {}
KnownAreas["Cove"].MainAreas ={
			{x1 = 2200, y1 = 1110, w = 50, h = 50, map = 0};
			{x1 = 2200, y1 = 1160, w = 86, h = 86, map = 0};
			
			{x1 = 2200, y1 = 1110, w = 50, h = 50, map = 1};
			{x1 = 2200, y1 = 1160, w = 86, h = 86, map = 1};
}
KnownAreas["Cove"].Guarded = true
KnownAreas["Cove"].SubAreas = {}
	KnownAreas["Cove"].SubAreas["Banks"] = {}
	KnownAreas["Cove"].SubAreas["Banks"].Squares = {
			{x1 = 2225, y1 = 1195, x2 = 2230, y2 = 1201, map = 0, name="Bank of Cove"};
			{x1 = 2225, y1 = 1195, x2 = 2230, y2 = 1201, map = 1, name="Bank of Cove"};
	}
	KnownAreas["Cove"].SubAreas["Shops"] = {}
	KnownAreas["Cove"].SubAreas["Shops"].Squares = {
			{x1 = 2240, y1 = 1224, x2 = 2246, y2 = 1238, map = 0, name="The Healing Hand"};
			{x1 = 2212, y1 = 1185, x2 = 2218, y2 = 1198, map = 0, name="The Farmer's Market"};
			{x1 = 2208, y1 = 1164, x2 = 2222, y2 = 1170, map = 0, name="The Warrior's Supplies"};
			{x1 = 2208, y1 = 1112, x2 = 2214, y2 = 1118, map = 0, name="Watch Tower"};
			
			{x1 = 2225, y1 = 1195, x2 = 2230, y2 = 1201, map = 1, name="Bank of Cove"};
			{x1 = 2240, y1 = 1224, x2 = 2246, y2 = 1238, map = 1, name="The Healing Hand"};
			{x1 = 2212, y1 = 1185, x2 = 2218, y2 = 1198, map = 1, name="The Farmer's Market"};
			{x1 = 2208, y1 = 1164, x2 = 2222, y2 = 1170, map = 1, name="The Warrior's Supplies"};
			{x1 = 2208, y1 = 1112, x2 = 2214, y2 = 1118, map = 1, name="Watch Tower"};
	}
-------------------------------------------------------------------
KnownAreas["Cove Orc Fort"] = {}
KnownAreas["Cove Orc Fort"].MainAreas ={
			{x1 = 2161, y1 = 1321, x2 = 2183, y2 = 1335, map = 0};
			{x1 = 2168, y1 = 1336, x2 = 2174, y2 = 1342, map = 0};
			{x1 = 2152, y1 = 1344, x2 = 2190, y2 = 1367, map = 0};
			{x1 = 2152, y1 = 1368, x2 = 2159, y2 = 1372, map = 0};
			{x1 = 2160, y1 = 1368, x2 = 2206, y2 = 1382, map = 0};
			{x1 = 2200, y1 = 1360, x2 = 2206, y2 = 1366, map = 0};
			{x1 = 2176, y1 = 1383, x2 = 2198, y2 = 1398, map = 0};
			{x1 = 2184, y1 = 1399, x2 = 2191, y2 = 1425, map = 0};
			
			{x1 = 2161, y1 = 1321, x2 = 2183, y2 = 1335, map = 1};
			{x1 = 2168, y1 = 1336, x2 = 2174, y2 = 1342, map = 1};
			{x1 = 2152, y1 = 1344, x2 = 2190, y2 = 1367, map = 1};
			{x1 = 2152, y1 = 1368, x2 = 2159, y2 = 1372, map = 1};
			{x1 = 2160, y1 = 1368, x2 = 2206, y2 = 1382, map = 1};
			{x1 = 2200, y1 = 1360, x2 = 2206, y2 = 1366, map = 1};
			{x1 = 2176, y1 = 1383, x2 = 2198, y2 = 1398, map = 1};
			{x1 = 2184, y1 = 1399, x2 = 2191, y2 = 1425, map = 1};
}
KnownAreas["Cove Orc Fort"].Guarded = false
KnownAreas["Cove Orc Fort"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Wind"] = {}
KnownAreas["Wind"].MainAreas ={
			{x1 = 5120, y1 = 0, w = 254, h = 254, map = 0};
			{x1 = 5120, y1 = 0, w = 254, h = 254, map = 1};
}
KnownAreas["Wind"].Guarded = true
KnownAreas["Wind"].SubAreas = {}
	KnownAreas["Wind"].SubAreas["Wind City"] = {}
	KnownAreas["Wind"].SubAreas["Wind City"].Guarded = true
	KnownAreas["Wind"].SubAreas["Wind City"].Squares = {
			{x1 = 5294, y1 = 19, w = 72, h = 120, map = 0 };
			{x1 = 5132, y1 = 58, w = 81, h = 68, map = 0 };
			{x1 = 5197, y1 = 126, w = 55, h = 78, map = 0 };
			{x1 = 5132, y1 = 3, w = 70, h = 55, map = 0 };
			{x1 = 5252, y1 = 112, w = 42, h = 58, map = 0 };
			{x1 = 5213, y1 = 98, w = 39, h = 28, map = 0 };
			{x1 = 5279, y1 = 57, w = 15, h = 55, map = 0 };
			{x1 = 5252, y1 = 170, w = 32, h = 8, map = 0 };
			{x1 = 5286, y1 = 25, w = 8, h = 32, map = 0 };
			{x1 = 5252, y1 = 178, w = 20, h = 5, map = 0 };
			{x1 = 5252, y1 = 183, w = 10, h = 10, map = 0 };
			
			{x1 = 5294, y1 = 19, w = 72, h = 120, map = 1 };
			{x1 = 5132, y1 = 58, w = 81, h = 68, map = 1 };
			{x1 = 5197, y1 = 126, w = 55, h = 78, map = 1 };
			{x1 = 5132, y1 = 3, w = 70, h = 55, map = 1 };
			{x1 = 5252, y1 = 112, w = 42, h = 58, map = 1 };
			{x1 = 5213, y1 = 98, w = 39, h = 28, map = 1 };
			{x1 = 5279, y1 = 57, w = 15, h = 55, map = 1 };
			{x1 = 5252, y1 = 170, w = 32, h = 8, map = 1 };
			{x1 = 5286, y1 = 25, w = 8, h = 32, map = 1 };
			{x1 = 5252, y1 = 178, w = 20, h = 5, map = 1 };
			{x1 = 5252, y1 = 183, w = 10, h = 10, map = 1 };
	}
	KnownAreas["Wind"].SubAreas["Tavern"] = {}
	KnownAreas["Wind"].SubAreas["Tavern"].Prior = true
	KnownAreas["Wind"].SubAreas["Tavern"].Squares = {
			{x1 = 5159, y1 = 15, w = 25, h = 9, z = 27, map = 0, name="Seeker's Inn"  };
			{x1 = 5159, y1 = 24, w = 9, h = 16, z = 27, map = 0, name="Seeker's Inn" };
			{x1 = 5159, y1 = 24, w = 9, h = 16, z = 17, map = 0, name="Seeker's Inn" };
			{x1 = 5175, y1 = 24, w = 9, h = 8, z = 27, map = 0, name="Seeker's Inn" };
			{x1 = 5212, y1 = 159, w = 9, h = 24, z = 5, map = 0, name="Windy Inn" };
			{x1 = 5221, y1 = 171, w = 7, h = 12, z = 5, map = 0, name="Windy Inn" };
			{x1 = 5206, y1 = 164, w = 6, h = 15, z = 5, map = 0, name="Windy Inn" };
			{x1 = 5303, y1 = 28, w = 16, h = 14, z = 40, map = 0, name="Bunkhouse"  };
			
			{x1 = 5159, y1 = 15, w = 25, h = 9, z = 27, map = 1, name="Seeker's Inn"  };
			{x1 = 5159, y1 = 24, w = 9, h = 16, z = 27, map = 1, name="Seeker's Inn" };
			{x1 = 5159, y1 = 24, w = 9, h = 16, z = 17, map = 1, name="Seeker's Inn" };
			{x1 = 5175, y1 = 24, w = 9, h = 8, z = 27, map = 1, name="Seeker's Inn" };
			{x1 = 5212, y1 = 159, w = 9, h = 24, z = 5, map = 1, name="Windy Inn" };
			{x1 = 5221, y1 = 171, w = 7, h = 12, z = 5, map = 1, name="Windy Inn" };
			{x1 = 5206, y1 = 164, w = 6, h = 15, z = 5, map = 1, name="Windy Inn" };
			{x1 = 5303, y1 = 28, w = 16, h = 14, z = 40, map = 1, name="Bunkhouse"  };
	}
	KnownAreas["Wind"].SubAreas["Banks"] = {}
	KnownAreas["Wind"].SubAreas["Banks"].Prior = true
	KnownAreas["Wind"].SubAreas["Banks"].Squares = {
			{x1 = 5341, y1 = 72, x2 = 5352, y2 = 77, z = 25, map = 0, name="Wind Bank"};
			{x1 = 5341, y1 = 78, x2 = 5349, y2 = 82, z = 25, map = 0, name="Wind Bank"};
			{x1 = 5341, y1 = 83, x2 = 5346, y2 = 86, z = 25, map = 0, name="Wind Bank"};
			
			{x1 = 5341, y1 = 72, x2 = 5352, y2 = 77, z = 25, map = 1, name="Wind Bank"};
			{x1 = 5341, y1 = 78, x2 = 5349, y2 = 82, z = 25, map = 1, name="Wind Bank"};
			{x1 = 5341, y1 = 83, x2 = 5346, y2 = 86, z = 25, map = 1, name="Wind Bank"};
	}
	KnownAreas["Wind"].SubAreas["Shops"] = {}
	KnownAreas["Wind"].SubAreas["Shops"].Prior = true
	KnownAreas["Wind"].SubAreas["Shops"].Squares = {
			{x1 = 5237, y1 = 172, x2 = 5247, y2 = 182, z = 15, map = 0, name="Seat of Knowledge"};
			{x1 = 5241, y1 = 184, x2 = 5247, y2 = 191, z = 15, map = 0, name="Seat of Knowledge"};
			{x1 = 5233, y1 = 135, x2 = 5239, y2 = 153, z = 15, map = 0, name="The Learned Mage"};
			{x1 = 5258, y1 = 123, x2 = 5270, y2 = 128, z = 20, map = 0, name="Wind Healer"};
			{x1 = 5258, y1 = 129, x2 = 5265, y2 = 135, z = 20, map = 0, name="Wind Healer"};
			{x1 = 5258, y1 = 136, x2 = 5261, y2 = 138, z = 20, map = 0, name="Wind Healer"};
			{x1 = 5291, y1 = 89, x2 = 5297, y2 = 98, z = 15, map = 0, name="The Alchemist of Wind"};
			{x1 = 5299, y1 = 87, x2 = 5309, y2 = 92, z = 15, map = 0, name="The Alchemist of Wind"};
			{x1 = 5341, y1 = 54, x2 = 5345, y2 = 55, z = 15, map = 0, name="Mage's Appetite"};
			{x1 = 5343, y1 = 56, x2 = 5345, y2 = 59, z = 15, map = 0, name="Mage's Appetite"};
			{x1 = 5352, y1 = 53, x2 = 5356, y2 = 59, z = 15, map = 0, name="Mage's Appetite"};
			{x1 = 5346, y1 = 50, x2 = 5351, y2 = 62, z = 15, map = 0, name="Mage's Appetite"};
			{x1 = 5209, y1 = 111, x2 = 5221, y2 = 122, z = 0, map = 0, name="Magical Supplies"};
			{x1 = 5149, y1 = 91, x2 = 5165, y2 = 99, z = 5, map = 0, name="Mage'sThings"};
			{x1 = 5151, y1 = 100, x2 = 5156, y2 = 106, z = 5, map = 0, name="Mage'sThings"};
			{x1 = 5197, y1 = 84, x2 = 5207, y2 = 88, z = 5, map = 0, name="Windy Clothes"};
			{x1 = 5197, y1 = 89, x2 = 5204, y2 = 93, z = 5, map = 0, name="Windy Clothes"};
			{x1 = 5197, y1 = 93, x2 = 5199, y2 = 96, z = 5, map = 0, name="Windy Clothes"};
			{x1 = 5144, y1 = 53, x2 = 5157, y2 = 65, z = 25, map = 0, name="Windy Alchemy"};
			{x1 = 5144, y1 = 65, x2 = 5150, y2 = 85, z = 25, map = 0, name="Windy Alchemy"};
			
			{x1 = 5237, y1 = 172, x2 = 5247, y2 = 182, z = 15, map = 1, name="Seat of Knowledge"};
			{x1 = 5241, y1 = 184, x2 = 5247, y2 = 191, z = 15, map = 1, name="Seat of Knowledge"};
			{x1 = 5233, y1 = 135, x2 = 5239, y2 = 153, z = 15, map = 1, name="The Learned Mage"};
			{x1 = 5258, y1 = 123, x2 = 5270, y2 = 128, z = 20, map = 1, name="Wind Healer"};
			{x1 = 5258, y1 = 129, x2 = 5265, y2 = 135, z = 20, map = 1, name="Wind Healer"};
			{x1 = 5258, y1 = 136, x2 = 5261, y2 = 138, z = 20, map = 1, name="Wind Healer"};
			{x1 = 5291, y1 = 89, x2 = 5297, y2 = 98, z = 15, map = 1, name="The Alchemist of Wind"};
			{x1 = 5299, y1 = 87, x2 = 5309, y2 = 92, z = 15, map = 1, name="The Alchemist of Wind"};
			{x1 = 5341, y1 = 54, x2 = 5345, y2 = 55, z = 15, map = 1, name="Mage's Appetite"};
			{x1 = 5343, y1 = 56, x2 = 5345, y2 = 59, z = 15, map = 1, name="Mage's Appetite"};
			{x1 = 5352, y1 = 53, x2 = 5356, y2 = 59, z = 15, map = 1, name="Mage's Appetite"};
			{x1 = 5346, y1 = 50, x2 = 5351, y2 = 62, z = 15, map = 1, name="Mage's Appetite"};
			{x1 = 5209, y1 = 111, x2 = 5221, y2 = 122, z = 0, map = 1, name="Magical Supplies"};
			{x1 = 5149, y1 = 91, x2 = 5165, y2 = 99, z = 5, map = 1, name="Mage'sThings"};
			{x1 = 5151, y1 = 100, x2 = 5156, y2 = 106, z = 5, map = 1, name="Mage'sThings"};
			{x1 = 5197, y1 = 84, x2 = 5207, y2 = 88, z = 5, map = 1, name="Windy Clothes"};
			{x1 = 5197, y1 = 89, x2 = 5204, y2 = 93, z = 5, map = 1, name="Windy Clothes"};
			{x1 = 5197, y1 = 93, x2 = 5199, y2 = 96, z = 5, map = 1, name="Windy Clothes"};
			{x1 = 5144, y1 = 53, x2 = 5157, y2 = 65, z = 25, map = 1, name="Windy Alchemy"};
			{x1 = 5144, y1 = 65, x2 = 5150, y2 = 85, z = 25, map = 1, name="Windy Alchemy"};
	}
-------------------------------------------------------------------
KnownAreas["Delucia"] = {}
KnownAreas["Delucia"].MainAreas ={
		{x1 = 5123, y1 = 3942, w = 192, h = 122, map = 0 };
		{x1 = 5147, y1 = 4064, w = 125, h = 20, map = 0 };
		{x1 = 5235, y1 = 3930, w = 80, h = 12, map = 0 };
		
		{x1 = 5123, y1 = 3942, w = 192, h = 122, map = 1 };
		{x1 = 5147, y1 = 4064, w = 125, h = 20, map = 1 };
		{x1 = 5235, y1 = 3930, w = 80, h = 12, map = 1 };
}
KnownAreas["Delucia"].Guarded = true
KnownAreas["Delucia"].SubAreas = {}
	KnownAreas["Delucia"].SubAreas["Tavern"] = {}
	KnownAreas["Delucia"].SubAreas["Tavern"].Squares = {
			{x1 = 5194, y1 = 4053, w = 10, h = 18, map = 0, name="The Barely Inn"  };
			{x1 = 5194, y1 = 4053, w = 10, h = 18, map = 1, name="The Barely Inn"  };
	}
	KnownAreas["Delucia"].SubAreas["Banks"] = {}
	KnownAreas["Delucia"].SubAreas["Banks"].Squares = {
			{x1 = 5262, y1 = 3977, x2 = 5267, y2 = 3986, map = 0, name="Ye Olde Eleventh Bank"};
			{x1 = 5269, y1 = 3971, x2 = 5276, y2 = 3986, map = 0, name="Ye Olde Eleventh Bank"};
			
			{x1 = 5262, y1 = 3977, x2 = 5267, y2 = 3986, map = 1, name="Ye Olde Eleventh Bank"};
			{x1 = 5269, y1 = 3971, x2 = 5276, y2 = 3986, map = 1, name="Ye Olde Eleventh Bank"};
	}
	KnownAreas["Delucia"].SubAreas["Shops"] = {}
	KnownAreas["Delucia"].SubAreas["Shops"].Squares = {
			{x1 = 5280, y1 = 3973, x2 = 5301, y2 = 3985, map = 1, name="Huts of Magics"};
			{x1 = 5291, y1 = 3996, x2 = 5302, y2 = 4014, map = 1, name="Delucia Stable"};
			{x1 = 5230, y1 = 4014, x2 = 5236, y2 = 4026, map = 1, name="Delucia Tailor"};
			{x1 = 5213, y1 = 4007, x2 = 5222, y2 = 4016, map = 1, name="The Supply Depot"};
			{x1 = 5223, y1 = 4002, x2 = 5230, y2 = 4006, map = 1, name="Zoot's Hammer"};
			{x1 = 5182, y1 = 3980, x2 = 5199, y2 = 3997, map = 1, name="Healer's Hut"};
	}
-------------------------------------------------------------------
KnownAreas["Papua"] = {}
KnownAreas["Papua"].MainAreas ={
		{x1 = 5639, y1 = 3095, w = 192, h = 223, map = 0 };
		{x1 = 5831, y1 = 3237, w = 20, h = 30, map = 0 };
		
		{x1 = 5639, y1 = 3095, w = 192, h = 223, map = 1 };
		{x1 = 5831, y1 = 3237, w = 20, h = 30, map = 1 };
}
KnownAreas["Papua"].Guarded = true
KnownAreas["Papua"].SubAreas = {}
	KnownAreas["Papua"].SubAreas["Tavern"] = {}
	KnownAreas["Papua"].SubAreas["Tavern"].Squares = {
			{x1 = 5757, y1 = 3150, x2 = 5787, y2 = 3173, map = 0, name="The Just Inn" };
			{x1 = 5757, y1 = 3150, x2 = 5787, y2 = 3173, map = 1, name="The Just Inn" };
	}
	KnownAreas["Papua"].SubAreas["Banks"] = {}
	KnownAreas["Papua"].SubAreas["Banks"].Squares = {
			{x1 = 5660, y1 = 3123, x2 = 5678, y2 = 3137, map = 0, name="Ye Olde Loan & Savings"};
			{x1 = 5660, y1 = 3123, x2 = 5678, y2 = 3137, map = 1, name="Ye Olde Loan & Savings"};
	}
	KnownAreas["Papua"].SubAreas["Shops"] = {}
	KnownAreas["Papua"].SubAreas["Shops"].Squares = {
			{x1 = 5654, y1 = 3143, x2 = 5668, y2 = 3153, map = 0, name="Strange Rocks"};
			{x1 = 5687, y1 = 3204, x2 = 5701, y2 = 3214, map = 0, name="The Carpentry House"};
			{x1 = 5711, y1 = 3196, x2 = 5717, y2 = 3206, map = 0, name="The Reagent Shoppe"};
			{x1 = 5707, y1 = 3204, x2 = 5711, y2 = 3206, map = 0, name="The Reagent Shoppe"};
			{x1 = 5724, y1 = 3188, x2 = 5738, y2 = 3198, map = 0, name="Tricks of the Trade"};
			{x1 = 5724, y1 = 3184, x2 = 5734, y2 = 3201, map = 0, name="Tricks of the Trade"};
			{x1 = 5742, y1 = 3189, x2 = 5748, y2 = 3207, map = 0, name="Nature's Best Baked Goods"};
			{x1 = 5749, y1 = 3189, x2 = 5760, y2 = 3199, map = 0, name="Nature's Best Baked Goods"};
			{x1 = 5732, y1 = 3216, x2 = 5738, y2 = 3226, map = 0, name="The Healing Hand"};
			{x1 = 5723, y1 = 3240, x2 = 5730, y2 = 3247, map = 0, name="Tinker's Paradise"};
			{x1 = 5733, y1 = 3258, x2 = 5741, y2 = 3263, map = 0, name="Adventure Outfitters"};
			{x1 = 5733, y1 = 3264, x2 = 5738, y2 = 3270, map = 0, name="Adventure Outfitters"};
			{x1 = 5750, y1 = 3268, x2 = 5756, y2 = 3275, map = 0, name="Papua Tailor"};
			{x1 = 5696, y1 = 3275, x2 = 5701, y2 = 3290, map = 0, name="The Southside Butchery"};
			{x1 = 5690, y1 = 3284, x2 = 5694, y2 = 3290, map = 0, name="The Southside Butchery"};
			{x1 = 5666, y1 = 3283, x2 = 5676, y2 = 3289, map = 0, name="Southside Stables"};
			{x1 = 5673, y1 = 3287, x2 = 5683, y2 = 3300, map = 0, name="Southside Stables"};
			{x1 = 5799, y1 = 3265, x2 = 5814, y2 = 3275, map = 0, name="Pier 39"};
			{x1 = 5799, y1 = 3277, x2 = 5811, y2 = 3279, map = 0, name="Pier 39"};
			{x1 = 5793, y1 = 3287, x2 = 5799, y2 = 3293, map = 0, name="The Revenge Shoppe"};
			{x1 = 5809, y1 = 3287, x2 = 5815, y2 = 3293, map = 0, name="The Revenge Shoppe"};
			{x1 = 5793, y1 = 3295, x2 = 5815, y2 = 3305, map = 0, name="The Revenge Shoppe"};
			
			{x1 = 5654, y1 = 3143, x2 = 5668, y2 = 3153, map = 1, name="Strange Rocks"};
			{x1 = 5687, y1 = 3204, x2 = 5701, y2 = 3214, map = 1, name="The Carpentry House"};
			{x1 = 5711, y1 = 3196, x2 = 5717, y2 = 3206, map = 1, name="The Reagent Shoppe"};
			{x1 = 5707, y1 = 3204, x2 = 5711, y2 = 3206, map = 1, name="The Reagent Shoppe"};
			{x1 = 5724, y1 = 3188, x2 = 5738, y2 = 3198, map = 1, name="Tricks of the Trade"};
			{x1 = 5724, y1 = 3184, x2 = 5734, y2 = 3201, map = 1, name="Tricks of the Trade"};
			{x1 = 5742, y1 = 3189, x2 = 5748, y2 = 3207, map = 1, name="Nature's Best Baked Goods"};
			{x1 = 5749, y1 = 3189, x2 = 5760, y2 = 3199, map = 1, name="Nature's Best Baked Goods"};
			{x1 = 5732, y1 = 3216, x2 = 5738, y2 = 3226, map = 1, name="The Healing Hand"};
			{x1 = 5723, y1 = 3240, x2 = 5730, y2 = 3247, map = 1, name="Tinker's Paradise"};
			{x1 = 5733, y1 = 3258, x2 = 5741, y2 = 3263, map = 1, name="Adventure Outfitters"};
			{x1 = 5733, y1 = 3264, x2 = 5738, y2 = 3270, map = 1, name="Adventure Outfitters"};
			{x1 = 5750, y1 = 3268, x2 = 5756, y2 = 3275, map = 1, name="Papua Tailor"};
			{x1 = 5696, y1 = 3275, x2 = 5701, y2 = 3290, map = 1, name="The Southside Butchery"};
			{x1 = 5690, y1 = 3284, x2 = 5694, y2 = 3290, map = 1, name="The Southside Butchery"};
			{x1 = 5666, y1 = 3283, x2 = 5676, y2 = 3289, map = 1, name="Southside Stables"};
			{x1 = 5673, y1 = 3287, x2 = 5683, y2 = 3300, map = 1, name="Southside Stables"};
			{x1 = 5799, y1 = 3265, x2 = 5814, y2 = 3275, map = 1, name="Pier 39"};
			{x1 = 5799, y1 = 3277, x2 = 5811, y2 = 3279, map = 1, name="Pier 39"};
			{x1 = 5793, y1 = 3287, x2 = 5799, y2 = 3293, map = 1, name="The Revenge Shoppe"};
			{x1 = 5809, y1 = 3287, x2 = 5815, y2 = 3293, map = 1, name="The Revenge Shoppe"};
			{x1 = 5793, y1 = 3295, x2 = 5815, y2 = 3305, map = 1, name="The Revenge Shoppe"};
	}
-------------------------------------------------------------------
KnownAreas["Buccaneer's Den"] = {}
KnownAreas["Buccaneer's Den"].MainAreas ={
		{x1 = 2612, y1 = 2057, w = 164, h = 210, map = 0 };
		{x1 = 2604, y1 = 2065, w = 8, h = 189, map = 0 };
		
		{x1 = 2612, y1 = 2057, w = 164, h = 210, map = 1 };
		{x1 = 2604, y1 = 2065, w = 8, h = 189, map = 1 };
}
KnownAreas["Buccaneer's Den"].Guarded = false
KnownAreas["Buccaneer's Den"].SubAreas = {}
	KnownAreas["Buccaneer's Den"].SubAreas["Tavern"] = {}
	KnownAreas["Buccaneer's Den"].SubAreas["Tavern"].Squares = {
			{x1 = 2664, y1 = 2232, x2 = 2670, y2 = 2238, map = 0, name="The Pirate's Plunder"};
			{x1 = 2672, y1 = 2232, x2 = 2686, y2 = 2246, map = 0, name="The Pirate's Plunder"};
			{x1 = 2712, y1 = 2080, x2 = 2718, y2 = 2102, map = 0, name="The Peg Leg Inn"};
			{x1 = 2720, y1 = 2080, x2 = 2726, y2 = 2095, map = 0, name="The Peg Leg Inn"};
			
			{x1 = 2664, y1 = 2232, x2 = 2670, y2 = 2238, map = 1, name="The Pirate's Plunder"};
			{x1 = 2672, y1 = 2232, x2 = 2686, y2 = 2246, map = 1, name="The Pirate's Plunder"};
			{x1 = 2712, y1 = 2080, x2 = 2718, y2 = 2102, map = 1, name="The Peg Leg Inn"};
			{x1 = 2720, y1 = 2080, x2 = 2726, y2 = 2095, map = 1, name="The Peg Leg Inn"};
	}
	KnownAreas["Buccaneer's Den"].SubAreas["Banks"] = {}
	KnownAreas["Buccaneer's Den"].SubAreas["Banks"].Squares = {
			{x1 = 2728, y1 = 2184, x2 = 2734, y2 = 2190, map = 0, name="Bank of Buccaneer's Den"};
			{x1 = 2728, y1 = 2184, x2 = 2734, y2 = 2190, map = 1, name="Bank of Buccaneer's Den"};
	}
	KnownAreas["Buccaneer's Den"].SubAreas["Shops"] = {}
	KnownAreas["Buccaneer's Den"].SubAreas["Shops"].Squares = {
			{x1 = 2728, y1 = 2248, x2 = 2742, y2 = 2254, map = 0, name="Pirate's Provisioner"};
			{x1 = 2728, y1 = 2255, x2 = 2734, y2 = 2262, map = 0, name="Pirate's Provisioner"};
			{x1 = 2752, y1 = 2216, x2 = 2758, y2 = 2222, map = 0, name="Buccaneer's Den Veterinarian"};
			{x1 = 2656, y1 = 2184, x2 = 2662, y2 = 2206, map = 0, name="Pirate's Den"};
			{x1 = 2648, y1 = 2192, x2 = 2654, y2 = 2198, map = 0, name="Pirate's Den"};
			{x1 = 2704, y1 = 2128, x2 = 2710, y2 = 2150, map = 0, name="Healer of Buccaneer's Den"};
			{x1 = 2704, y1 = 2176, x2 = 2710, y2 = 2182, map = 0, name="Buccaneer's Den Leatherworks"};
			{x1 = 2664, y1 = 2072, x2 = 2670, y2 = 2078, map = 0, name="Buccaneer's Den Bath"};
			{x1 = 2656, y1 = 2080, x2 = 2678, y2 = 2094, map = 0, name="Buccaneer's Den Bath"};
			{x1 = 2632, y1 = 2080, x2 = 2638, y2 = 2086, map = 0, name="Cutlass Smithing"};
			{x1 = 2624, y1 = 2096, x2 = 2630, y2 = 2102, map = 0, name="Violente Woodworks"};
			
			{x1 = 2728, y1 = 2248, x2 = 2742, y2 = 2254, map = 1, name="Pirate's Provisioner"};
			{x1 = 2728, y1 = 2255, x2 = 2734, y2 = 2262, map = 1, name="Pirate's Provisioner"};
			{x1 = 2752, y1 = 2216, x2 = 2758, y2 = 2222, map = 1, name="Buccaneer's Den Veterinarian"};
			{x1 = 2656, y1 = 2184, x2 = 2662, y2 = 2206, map = 1, name="Pirate's Den"};
			{x1 = 2648, y1 = 2192, x2 = 2654, y2 = 2198, map = 1, name="Pirate's Den"};
			{x1 = 2704, y1 = 2128, x2 = 2710, y2 = 2150, map = 1, name="Healer of Buccaneer's Den"};
			{x1 = 2704, y1 = 2176, x2 = 2710, y2 = 2182, map = 1, name="Buccaneer's Den Leatherworks"};
			{x1 = 2664, y1 = 2072, x2 = 2670, y2 = 2078, map = 1, name="Buccaneer's Den Bath"};
			{x1 = 2656, y1 = 2080, x2 = 2678, y2 = 2094, map = 1, name="Buccaneer's Den Bath"};
			{x1 = 2632, y1 = 2080, x2 = 2638, y2 = 2086, map = 1, name="Cutlass Smithing"};
			{x1 = 2624, y1 = 2096, x2 = 2630, y2 = 2102, map = 1, name="Violente Woodworks"};
	}
-------------------------------------------------------------------
KnownAreas["Nujel'm"] = {}
KnownAreas["Nujel'm"].MainAreas ={
		{x1 = 3475, y1 = 1000, w = 360, h = 435, map = 0 };
		
		{x1 = 3475, y1 = 1000, w = 360, h = 435, map = 1 };
}
KnownAreas["Nujel'm"].Guarded = true
KnownAreas["Nujel'm"].SubAreas = {}
	KnownAreas["Nujel'm"].SubAreas["Tavern"] = {}
	KnownAreas["Nujel'm"].SubAreas["Tavern"].Squares = {
			{x1 = 3729, y1 = 1288, x2 = 3750, y2 = 1342, map = 0, name="Restful Slumber"};
			{x1 = 3728, y1 = 1248, x2 = 3750, y2 = 1270, map = 0, name="The Silver Bow"};
			{x1 = 3760, y1 = 1216, x2 = 3770, y2 = 1238, map = 0, name="Mystical Spirits"};
			{x1 = 3771, y1 = 1220, x2 = 3774, y2 = 1234, map = 0, name="Mystical Spirits"};
			{x1 = 3776, y1 = 1224, x2 = 3782, y2 = 1230, map = 0, name="Mystical Spirits"};
						
			{x1 = 3729, y1 = 1288, x2 = 3750, y2 = 1342, map = 1, name="Restful Slumber"};
			{x1 = 3728, y1 = 1248, x2 = 3750, y2 = 1270, map = 1, name="The Silver Bow"};
			{x1 = 3760, y1 = 1216, x2 = 3770, y2 = 1238, map = 1, name="Mystical Spirits"};
			{x1 = 3771, y1 = 1220, x2 = 3774, y2 = 1234, map = 1, name="Mystical Spirits"};
			{x1 = 3776, y1 = 1224, x2 = 3782, y2 = 1230, map = 1, name="Mystical Spirits"};
	}
	KnownAreas["Nujel'm"].SubAreas["Banks"] = {}
	KnownAreas["Nujel'm"].SubAreas["Banks"].Squares = {
			{x1 = 3760, y1 = 1312, x2 = 3766, y2 = 1326, map = 0, name="Bank of Nujel'm"};
			
			{x1 = 3760, y1 = 1312, x2 = 3766, y2 = 1326, map = 1, name="Bank of Nujel'm"};
	}
	KnownAreas["Nujel'm"].SubAreas["Shops"] = {}
	KnownAreas["Nujel'm"].SubAreas["Shops"].Squares = {
			{x1 = 3760, y1 = 1248, x2 = 3782, y2 = 1270, map = 0, name="Tailor of the Isle"};
			{x1 = 3728, y1 = 1216, x2 = 3750, y2 = 1238, map = 0, name="Nujel'm Theater"};
			{x1 = 3736, y1 = 1184, x2 = 3750, y2 = 1205, map = 0, name="Bardic Guild"};
			{x1 = 3729, y1 = 1193, x2 = 3734, y2 = 1205, map = 0, name="Bardic Guild"};
			{x1 = 3760, y1 = 1184, x2 = 3782, y2 = 1194, map = 0, name="Counselor's Guild"};
			{x1 = 3760, y1 = 1195, x2 = 3770, y2 = 1206, map = 0, name="Counselor's Guild"};
			{x1 = 3768, y1 = 1160, x2 = 3781, y2 = 1173, map = 0, name="Jewel of the Isle"};
			{x1 = 3704, y1 = 1224, x2 = 3718, y2 = 1230, map = 0, name="Seaborne Ships"};
			{x1 = 3696, y1 = 1208, x2 = 3702, y2 = 1222, map = 0, name="Seaborne Ships"};
			{x1 = 3552, y1 = 1200, x2 = 3558, y2 = 1206, map = 0, name="Public Smithing"};
			{x1 = 3545, y1 = 1193, x2 = 3550, y2 = 1198, map = 0, name="Nujel'm Bowry"};
			{x1 = 3545, y1 = 1185, x2 = 3550, y2 = 1190, map = 0, name="Nujel'm Blacksmith"};
			{x1 = 3544, y1 = 1176, x2 = 3550, y2 = 1182, map = 0, name="Nujel'm Tannery"};
			{x1 = 3553, y1 = 1168, x2 = 3558, y2 = 1174, map = 0, name="Shipwright"};
			{x1 = 3709, y1 = 1376, x2 = 3718, y2 = 1386, map = 0, name="Debtor's Prison"};
			{x1 = 3713, y1 = 1392, x2 = 3730, y2 = 1410, map = 0, name="Nujel'm Court"};
			{x1 = 3731, y1 = 1400, x2 = 3738, y2 = 1410, map = 0, name="Nujel'm Court"};
			{x1 = 3718, y1 = 1408, x2 = 3723, y2 = 1413, map = 0, name="Nujel'm Court"};
			
			{x1 = 3760, y1 = 1248, x2 = 3782, y2 = 1270, map = 1, name="Tailor of the Isle"};
			{x1 = 3728, y1 = 1216, x2 = 3750, y2 = 1238, map = 1, name="Nujel'm Theater"};
			{x1 = 3736, y1 = 1184, x2 = 3750, y2 = 1205, map = 1, name="Bardic Guild"};
			{x1 = 3729, y1 = 1193, x2 = 3734, y2 = 1205, map = 1, name="Bardic Guild"};
			{x1 = 3760, y1 = 1184, x2 = 3782, y2 = 1194, map = 1, name="Counselor's Guild"};
			{x1 = 3760, y1 = 1195, x2 = 3770, y2 = 1206, map = 1, name="Counselor's Guild"};
			{x1 = 3768, y1 = 1160, x2 = 3781, y2 = 1173, map = 1, name="Jewel of the Isle"};
			{x1 = 3704, y1 = 1224, x2 = 3718, y2 = 1230, map = 1, name="Seaborne Ships"};
			{x1 = 3696, y1 = 1208, x2 = 3702, y2 = 1222, map = 1, name="Seaborne Ships"};
			{x1 = 3552, y1 = 1200, x2 = 3558, y2 = 1206, map = 1, name="Public Smithing"};
			{x1 = 3545, y1 = 1193, x2 = 3550, y2 = 1198, map = 1, name="Nujel'm Bowry"};
			{x1 = 3545, y1 = 1185, x2 = 3550, y2 = 1190, map = 1, name="Nujel'm Blacksmith"};
			{x1 = 3544, y1 = 1176, x2 = 3550, y2 = 1182, map = 1, name="Nujel'm Tannery"};
			{x1 = 3553, y1 = 1168, x2 = 3558, y2 = 1174, map = 1, name="Shipwright"};
			{x1 = 3709, y1 = 1376, x2 = 3718, y2 = 1386, map = 1, name="Debtor's Prison"};
			{x1 = 3713, y1 = 1392, x2 = 3730, y2 = 1410, map = 1, name="Nujel'm Court"};
			{x1 = 3731, y1 = 1400, x2 = 3738, y2 = 1410, map = 1, name="Nujel'm Court"};
			{x1 = 3718, y1 = 1408, x2 = 3723, y2 = 1413, map = 1, name="Nujel'm Court"};
	}
	KnownAreas["Nujel'm"].SubAreas["Graveyard"] = {}
	KnownAreas["Nujel'm"].SubAreas["Graveyard"].Squares = {
			{x1 = 3502, y1 = 1140, x2 = 3530, y2 = 1161, map = 0, name="Nujel'm Graveyard"};
			{x1 = 3518, y1 = 1122, x2 = 3538, y2 = 1151, map = 0, name="Nujel'm Graveyard"};
			{x1 = 3539, y1 = 1128, x2 = 3542, y2 = 1151, map = 0, name="Nujel'm Graveyard"};
			{x1 = 3543, y1 = 1143, x2 = 3552, y2 = 1151, map = 0, name="Nujel'm Graveyard"};
			
			{x1 = 3502, y1 = 1140, x2 = 3530, y2 = 1161, map = 1, name="Nujel'm Graveyard"};
			{x1 = 3518, y1 = 1122, x2 = 3538, y2 = 1151, map = 1, name="Nujel'm Graveyard"};
			{x1 = 3539, y1 = 1128, x2 = 3542, y2 = 1151, map = 1, name="Nujel'm Graveyard"};
			{x1 = 3543, y1 = 1143, x2 = 3552, y2 = 1151, map = 1, name="Nujel'm Graveyard"};
	}
-------------------------------------------------------------------
KnownAreas["Floating Market"] = {}
KnownAreas["Floating Market"].MainAreas ={
		{x1 = 4530, y1 = 2298, x2 = 4573, y2 = 2407, map = 0};
		{x1 = 4530, y1 = 2298, x2 = 4573, y2 = 2407, map = 1};
}
KnownAreas["Floating Market"].Guarded = true
KnownAreas["Floating Market"].SubAreas = {}
	KnownAreas["Floating Market"].SubAreas["Tavern"] = {}
	KnownAreas["Floating Market"].SubAreas["Tavern"].Squares = {
			{x1 = 4540, y1 = 2298, x2 = 4546, y2 = 2307, map = 0, name="Winds Tavern"};
			{x1 = 4540, y1 = 2298, x2 = 4546, y2 = 2307, map = 1, name="Winds Tavern"};
	}
	KnownAreas["Floating Market"].SubAreas["Banks"] = {}
	KnownAreas["Floating Market"].SubAreas["Banks"].Squares = {
			{x1 = 4551, y1 = 2322, x2 = 4553, y2 = 2325, map = 0, name="Bank"};
			{x1 = 4551, y1 = 2322, x2 = 4553, y2 = 2325, map = 1, name="Bank"};
	}
	KnownAreas["Floating Market"].SubAreas["Shops"] = {}
	KnownAreas["Floating Market"].SubAreas["Shops"].Squares = {
			{x1 = 4537, y1 = 2317, x2 = 4541, y2 = 2326, map = 0, name="General Store"};
			{x1 = 4537, y1 = 2317, x2 = 4541, y2 = 2326, map = 1, name="General Store"};
	}
-------------------------------------------------------------------
KnownAreas["New Magincia"] = {}
KnownAreas["New Magincia"].MainAreas ={
		{x1 = 3627, y1 = 2032, x2 = 3816, y2 = 2277, map = 0};
		{x1 = 3627, y1 = 2032, x2 = 3816, y2 = 2277, map = 1};
}
KnownAreas["New Magincia"].Guarded = true
KnownAreas["New Magincia"].SubAreas = {}
	KnownAreas["New Magincia"].SubAreas["Tavern"] = {}
	KnownAreas["New Magincia"].SubAreas["Tavern"].Squares = {
			{x1 = 3687, y1 = 2246, x2 = 3698, y2 = 2261, map = 0, name="Modest Damsel"};
			{x1 = 3687, y1 = 2246, x2 = 3698, y2 = 2261, map = 1, name="Modest Damsel"};
			{x1 = 3767, y1 = 2124, x2 = 3780, y2 = 2137, map = 0, name="The Seaside Inn", shard=24};
	}
	KnownAreas["New Magincia"].SubAreas["PincoHQ"] = {}
	KnownAreas["New Magincia"].SubAreas["PincoHQ"].Squares = {
			{x1 = 3786, y1 = 2110, x2 = 3799, y2 = 2123, map = 0, name="The Pinco's Workshop", shard=24};
	}
	KnownAreas["New Magincia"].SubAreas["Banks"] = {}
	KnownAreas["New Magincia"].SubAreas["Banks"].Squares = {
			{x1 = 3784, y1 = 2240, x2 = 3790, y2 = 2254, map = 0, name="Bank of New Magincia"};
			{x1 = 3784, y1 = 2240, x2 = 3790, y2 = 2254, map = 1, name="Bank of New Magincia"};
	}
	KnownAreas["New Magincia"].SubAreas["Shops"] = {}
	KnownAreas["New Magincia"].SubAreas["Shops"].Squares = {
			{x1 = 4537, y1 = 2317, x2 = 4541, y2 = 2326, map = 0, name="General Store"};
			{x1 = 3663, y1 = 2103, x2 = 3682, y2 = 2122, map = 0, name="New Magincia Garden"};
			{x1 = 3717, y1 = 2062, x2 = 3724, y2 = 2069, map = 0, name="Gazebo"};
			
			{x1 = 4537, y1 = 2317, x2 = 4541, y2 = 2326, map = 1, name="General Store"};
			{x1 = 3663, y1 = 2103, x2 = 3682, y2 = 2122, map = 1, name="New Magincia Garden"};
			{x1 = 3717, y1 = 2062, x2 = 3724, y2 = 2069, map = 1, name="Gazebo"};
	}
-------------------------------------------------------------------
KnownAreas["Hidden Valley"] = {}
KnownAreas["Hidden Valley"].MainAreas ={
		{x1 = 1658, y1 = 2937, x2 = 1695, y2 = 3001, map = 0};
		{x1 = 1658, y1 = 2937, x2 = 1695, y2 = 3001, map = 1};
}
KnownAreas["Hidden Valley"].Guarded = true
KnownAreas["Hidden Valley"].SubAreas = {}
-------------------------------------------------------------------
KnownAreas["Vesper"] = {}
KnownAreas["Vesper"].MainAreas ={
		{x1 = 2893, y1 = 598, w = 121, h = 50, map = 0};
		{x1 = 2816, y1 = 648, w = 249, h = 365, map = 0};
		{x1 = 2734, y1 = 944, w = 82, h = 4, map = 0};
		{x1 = 2728, y1 = 948, w = 88, h = 53, map = 0};
		
		{x1 = 2893, y1 = 598, w = 121, h = 50, map = 1};
		{x1 = 2816, y1 = 648, w = 249, h = 365, map = 1};
		{x1 = 2734, y1 = 944, w = 82, h = 4, map = 1};
		{x1 = 2728, y1 = 948, w = 88, h = 53, map = 1};
}
KnownAreas["Vesper"].Guarded = true
KnownAreas["Vesper"].SubAreas = {}
	KnownAreas["Vesper"].SubAreas["Tavern"] = {}
	KnownAreas["Vesper"].SubAreas["Tavern"].Prior = true
	KnownAreas["Vesper"].SubAreas["Tavern"].Squares = {
			{x1 = 2952, y1 = 864, x2 = 2966, y2 = 894, map = 0, name="Vesper Youth Hostel"};
			{x1 = 2968, y1 = 872, x2 = 2974, y2 = 886, map = 0, name="Vesper Youth Hostel"};
			{x1 = 2892, y1 = 901, x2 = 2906, y2 = 918, map = 0, name="The Marsh Hall"};
			{x1 = 2908, y1 = 904, x2 = 2914, y2 = 910, map = 0, name="The Marsh Hall"};
			{x1 = 2851, y1 = 988, x2 = 2861, y2 = 1003, z= -21, map = 0, name="Hideout"};
			{x1 = 2776, y1 = 952, x2 = 2790, y2 = 982, map = 0, name="The Ironwood Inn"};
			{x1 = 2768, y1 = 960, x2 = 2774, y2 = 974, map = 0, name="The Ironwood Inn"};
			
			{x1 = 2952, y1 = 864, x2 = 2966, y2 = 894, map = 1, name="Vesper Youth Hostel"};
			{x1 = 2968, y1 = 872, x2 = 2974, y2 = 886, map = 1, name="Vesper Youth Hostel"};
			{x1 = 2892, y1 = 901, x2 = 2906, y2 = 918, map = 1, name="The Marsh Hall"};
			{x1 = 2908, y1 = 904, x2 = 2914, y2 = 910, map = 1, name="The Marsh Hall"};
			{x1 = 2851, y1 = 988, x2 = 2861, y2 = 1003, z= -21, map = 1, name="Hideout"};
			{x1 = 2776, y1 = 952, x2 = 2790, y2 = 982, map = 1, name="The Ironwood Inn"};
			{x1 = 2768, y1 = 960, x2 = 2774, y2 = 974, map = 1, name="The Ironwood Inn"};
	}
	KnownAreas["Vesper"].SubAreas["Banks"] = {}
	KnownAreas["Vesper"].SubAreas["Banks"].Squares = {
			{x1 = 2888, y1 = 672, x2 = 2894, y2 = 678, map = 0, name="The Mint of Vesper"};
			{x1 = 2872, y1 = 672, x2 = 2886, y2 = 694, map = 0, name="The Mint of Vesper"};
	
			{x1 = 2888, y1 = 672, x2 = 2894, y2 = 678, map = 1, name="The Mint of Vesper"};
			{x1 = 2872, y1 = 672, x2 = 2886, y2 = 694, map = 1, name="The Mint of Vesper"};
	}
	KnownAreas["Vesper"].SubAreas["Shops"] = {}
	KnownAreas["Vesper"].SubAreas["Shops"].Squares = {
			{x1 = 2881, y1 = 648, x2 = 2891, y2 = 654, map = 0, name="The Bubbling Brew" };
			{x1 = 2888, y1 = 656, x2 = 2894, y2 = 662, map = 0, name="The Bubbling Brew"};
			{x1 = 2912, y1 = 664, x2 = 2926, y2 = 678, map = 0, name="The Magical Light"};
			{x1 = 2896, y1 = 704, x2 = 2902, y2 = 710, map = 0, name="The Colored Canvas"};
			{x1 = 2905, y1 = 704, x2 = 2910, y2 = 718, map = 0, name="The Colored Canvas"};
			{x1 = 2872, y1 = 720, x2 = 2886, y2 = 726, map = 0, name="The Shimmering Jewel"};
			{x1 = 2872, y1 = 712, x2 = 2878, y2 = 718, map = 0, name="The Shimmering Jewel"};
			{x1 = 2895, y1 = 736, x2 = 2902, y2 = 742, map = 0, name="The Musician's Hall"};
			{x1 = 2880, y1 = 736, x2 = 2894, y2 = 750, map = 0, name="The Musician's Hall"};
			{x1 = 2952, y1 = 616, x2 = 2966, y2 = 630, map = 0, name="The Spinning Wheel"};
			{x1 = 2967, y1 = 616, x2 = 2974, y2 = 622, map = 0, name="The Spinning Wheel"};
			{x1 = 2976, y1 = 632, x2 = 2983, y2 = 638, map = 0, name="The Adventurers Supplies"};
			{x1 = 2984, y1 = 632, x2 = 2998, y2 = 646, map = 0, name="The Adventurers Supplies"};
			{x1 = 2952, y1 = 696, x2 = 2958, y2 = 702, map = 0, name="The Busy Bees"};
			{x1 = 2952, y1 = 704, x2 = 2966, y2 = 710, map = 0, name="The Busy Bees"};
			{x1 = 2993, y1 = 760, x2 = 3006, y2 = 766, map = 0, name="The Twisted Oven"};
			{x1 = 2984, y1 = 776, x2 = 2998, y2 = 782, map = 0, name="The Butcher's Knife"};
			{x1 = 3016, y1 = 760, x2 = 3030, y2 = 766, map = 0, name="Farmer's Market"};
			{x1 = 3008, y1 = 776, x2 = 3022, y2 = 782, map = 0, name="Fisherman's Wharf"};
			{x1 = 2952, y1 = 808, x2 = 2966, y2 = 822, map = 0, name="The Fishermen's Guild"};
			{x1 = 2967, y1 = 816, x2 = 2974, y2 = 822, map = 0, name="The Fishermen's Guild"};
			{x1 = 2992, y1 = 808, x2 = 3006, y2 = 814, map = 0, name="The Majestic Boat"};
			{x1 = 2992, y1 = 815, x2 = 2998, y2 = 822, map = 0, name="The Majestic Boat"};
			{x1 = 2992, y1 = 832, x2 = 2998, y2 = 846, map = 0, name="The Magician's Friend"};
			{x1 = 2984, y1 = 832, x2 = 2990, y2 = 838, map = 0, name="The Magician's Friend"};
			{x1 = 2912, y1 = 848, x2 = 2926, y2 = 862, map = 0, name="Healer of Vesper"};
			{x1 = 2936, y1 = 928, x2 = 2950, y2 = 942, map = 0, name="Vesper Customs"};
			{x1 = 2912, y1 = 968, x2 = 2934, y2 = 990, map = 0, name="Vesper Museum"};
			{x1 = 2912, y1 = 963, x2 = 2918, y2 = 967, map = 0, name="Vesper Museum"};
			{x1 = 2863, y1 = 997, x2 = 2869, y2 = 1003, map = 0, name="Tanner's Shop"};
			{x1 = 2855, y1 = 989, x2 = 2861, y2 = 1003, map = 0, name="Tanner's Shop"};
			{x1 = 2736, y1 = 976, x2 = 2750, y2 = 990, map = 0, name="Vesper Guard Tower"};
			{x1 = 2832, y1 = 936, x2 = 2854, y2 = 950, map = 0, name="Counselor's Guild"};
			{x1 = 2840, y1 = 928, x2 = 2846, y2 = 958, map = 0, name="Counselor's Guild"};
			{x1 = 2832, y1 = 896, x2 = 2846, y2 = 918, map = 0, name="The Champions of Light"};
			{x1 = 2846, y1 = 904, x2 = 2854, y2 = 910, map = 0, name="The Champions of Light"};
			{x1 = 2832, y1 = 876, x2 = 2838, y2 = 886, map = 0, name="The Spinning Wheel"};
			{x1 = 2839, y1 = 880, x2 = 2846, y2 = 886, map = 0, name="The Spinning Wheel"};
			{x1 = 2832, y1 = 865, x2 = 2838, y2 = 875, map = 0, name="The Adventurer's Friend"};
			{x1 = 2838, y1 = 865, x2 = 2846, y2 = 870, map = 0, name="The Adventurer's Friend"};
			{x1 = 2856, y1 = 848, x2 = 2870, y2 = 854, map = 0, name="The Ironworks"};
			{x1 = 2864, y1 = 856, x2 = 2870, y2 = 862, map = 0, name="The Ironworks"};
			{x1 = 2832, y1 = 793, x2 = 2846, y2 = 798, map = 0, name="Warrior's Companion"};
			{x1 = 2832, y1 = 807, x2 = 2846, y2 = 814, map = 0, name="Warrior's Companion"};
			{x1 = 2832, y1 = 799, x2 = 2838, y2 = 807, map = 0, name="Warrior's Companion"};
			{x1 = 2855, y1 = 807, x2 = 2867, y2 = 814, map = 0, name="Ranger's Tool"};
			{x1 = 2855, y1 = 800, x2 = 2858, y2 = 807, map = 0, name="Ranger's Tool"};
			{x1 = 2888, y1 = 784, x2 = 2894, y2 = 790, map = 0, name="The Gadget's Corner"};
			{x1 = 2896, y1 = 785, x2 = 2902, y2 = 798, map = 0, name="The Gadget's Corner"};
			{x1 = 2920, y1 = 792, x2 = 2926, y2 = 798, map = 0, name="The Hammer and Nail"};
			{x1 = 2912, y1 = 792, x2 = 2918, y2 = 806, map = 0, name="The Hammer and Nail"};
			{x1 = 2848, y1 = 728, x2 = 2862, y2 = 742, map = 0, name="The Ore of Vesper"};
			
			{x1 = 2881, y1 = 648, x2 = 2891, y2 = 654, map = 1, name="The Bubbling Brew" };
			{x1 = 2888, y1 = 656, x2 = 2894, y2 = 662, map = 1, name="The Bubbling Brew"};
			{x1 = 2912, y1 = 664, x2 = 2926, y2 = 678, map = 1, name="The Magical Light"};
			{x1 = 2896, y1 = 704, x2 = 2902, y2 = 710, map = 1, name="The Colored Canvas"};
			{x1 = 2905, y1 = 704, x2 = 2910, y2 = 718, map = 1, name="The Colored Canvas"};
			{x1 = 2872, y1 = 720, x2 = 2886, y2 = 726, map = 1, name="The Shimmering Jewel"};
			{x1 = 2872, y1 = 712, x2 = 2878, y2 = 718, map = 1, name="The Shimmering Jewel"};
			{x1 = 2895, y1 = 736, x2 = 2902, y2 = 742, map = 1, name="The Musician's Hall"};
			{x1 = 2880, y1 = 736, x2 = 2894, y2 = 750, map = 1, name="The Musician's Hall"};
			{x1 = 2952, y1 = 616, x2 = 2966, y2 = 630, map = 1, name="The Spinning Wheel"};
			{x1 = 2967, y1 = 616, x2 = 2974, y2 = 622, map = 1, name="The Spinning Wheel"};
			{x1 = 2976, y1 = 632, x2 = 2983, y2 = 638, map = 1, name="The Adventurers Supplies"};
			{x1 = 2984, y1 = 632, x2 = 2998, y2 = 646, map = 1, name="The Adventurers Supplies"};
			{x1 = 2952, y1 = 696, x2 = 2958, y2 = 702, map = 1, name="The Busy Bees"};
			{x1 = 2952, y1 = 704, x2 = 2966, y2 = 710, map = 1, name="The Busy Bees"};
			{x1 = 2993, y1 = 760, x2 = 3006, y2 = 766, map = 1, name="The Twisted Oven"};
			{x1 = 2984, y1 = 776, x2 = 2998, y2 = 782, map = 1, name="The Butcher's Knife"};
			{x1 = 3016, y1 = 760, x2 = 3030, y2 = 766, map = 1, name="Farmer's Market"};
			{x1 = 3008, y1 = 776, x2 = 3022, y2 = 782, map = 1, name="Fisherman's Wharf"};
			{x1 = 2952, y1 = 808, x2 = 2966, y2 = 822, map = 1, name="The Fishermen's Guild"};
			{x1 = 2967, y1 = 816, x2 = 2974, y2 = 822, map = 1, name="The Fishermen's Guild"};
			{x1 = 2992, y1 = 808, x2 = 3006, y2 = 814, map = 1, name="The Majestic Boat"};
			{x1 = 2992, y1 = 815, x2 = 2998, y2 = 822, map = 1, name="The Majestic Boat"};
			{x1 = 2992, y1 = 832, x2 = 2998, y2 = 846, map = 1, name="The Magician's Friend"};
			{x1 = 2984, y1 = 832, x2 = 2990, y2 = 838, map = 1, name="The Magician's Friend"};
			{x1 = 2912, y1 = 848, x2 = 2926, y2 = 862, map = 1, name="Healer of Vesper"};
			{x1 = 2936, y1 = 928, x2 = 2950, y2 = 942, map = 1, name="Vesper Customs"};
			{x1 = 2912, y1 = 968, x2 = 2934, y2 = 990, map = 1, name="Vesper Museum"};
			{x1 = 2912, y1 = 963, x2 = 2918, y2 = 967, map = 1, name="Vesper Museum"};
			{x1 = 2863, y1 = 997, x2 = 2869, y2 = 1003, map = 1, name="Tanner's Shop"};
			{x1 = 2855, y1 = 989, x2 = 2861, y2 = 1003, map = 1, name="Tanner's Shop"};
			{x1 = 2736, y1 = 976, x2 = 2750, y2 = 990, map = 1, name="Vesper Guard Tower"};
			{x1 = 2832, y1 = 936, x2 = 2854, y2 = 950, map = 1, name="Counselor's Guild"};
			{x1 = 2840, y1 = 928, x2 = 2846, y2 = 958, map = 1, name="Counselor's Guild"};
			{x1 = 2832, y1 = 896, x2 = 2846, y2 = 918, map = 1, name="The Champions of Light"};
			{x1 = 2846, y1 = 904, x2 = 2854, y2 = 910, map = 1, name="The Champions of Light"};
			{x1 = 2832, y1 = 876, x2 = 2838, y2 = 886, map = 1, name="The Spinning Wheel"};
			{x1 = 2839, y1 = 880, x2 = 2846, y2 = 886, map = 1, name="The Spinning Wheel"};
			{x1 = 2832, y1 = 865, x2 = 2838, y2 = 875, map = 1, name="The Adventurer's Friend"};
			{x1 = 2838, y1 = 865, x2 = 2846, y2 = 870, map = 1, name="The Adventurer's Friend"};
			{x1 = 2856, y1 = 848, x2 = 2870, y2 = 854, map = 1, name="The Ironworks"};
			{x1 = 2864, y1 = 856, x2 = 2870, y2 = 862, map = 1, name="The Ironworks"};
			{x1 = 2832, y1 = 793, x2 = 2846, y2 = 798, map = 1, name="Warrior's Companion"};
			{x1 = 2832, y1 = 807, x2 = 2846, y2 = 814, map = 1, name="Warrior's Companion"};
			{x1 = 2832, y1 = 799, x2 = 2838, y2 = 807, map = 1, name="Warrior's Companion"};
			{x1 = 2855, y1 = 807, x2 = 2867, y2 = 814, map = 1, name="Ranger's Tool"};
			{x1 = 2855, y1 = 800, x2 = 2858, y2 = 807, map = 1, name="Ranger's Tool"};
			{x1 = 2888, y1 = 784, x2 = 2894, y2 = 790, map = 1, name="The Gadget's Corner"};
			{x1 = 2896, y1 = 785, x2 = 2902, y2 = 798, map = 1, name="The Gadget's Corner"};
			{x1 = 2920, y1 = 792, x2 = 2926, y2 = 798, map = 1, name="The Hammer and Nail"};
			{x1 = 2912, y1 = 792, x2 = 2918, y2 = 806, map = 1, name="The Hammer and Nail"};
			{x1 = 2848, y1 = 728, x2 = 2862, y2 = 742, map = 1, name="The Ore of Vesper"};
	}
-------------------------------------------------------------------
KnownAreas["Serpent's Hold"] = {}
KnownAreas["Serpent's Hold"].MainAreas ={
		{x1 = 2868, y1 = 3324, w = 205, h = 195, map = 0};
		{x1 = 2868, y1 = 3324, w = 205, h = 195, map = 1};
}
KnownAreas["Serpent's Hold"].Guarded = true
KnownAreas["Serpent's Hold"].SubAreas = {}
	KnownAreas["Serpent's Hold"].SubAreas["Tavern"] = {}
	KnownAreas["Serpent's Hold"].SubAreas["Tavern"].Squares = {
			{x1 = 2968, y1 = 3416, x2 = 2974, y2 = 3430, map = 0, name="The Dog and Lion Pub"};
			{x1 = 2960, y1 = 3400, x2 = 2974, y2 = 3414, map = 0, name="The Broken Arrow Inn"};
			{x1 = 3008, y1 = 3450, x2 = 3020, y2 = 3462, map = 0, name="Fisherman's Brew"};
			
			{x1 = 2968, y1 = 3416, x2 = 2974, y2 = 3430, map = 1, name="The Dog and Lion Pub"};
			{x1 = 2960, y1 = 3400, x2 = 2974, y2 = 3414, map = 1, name="The Broken Arrow Inn"};
			{x1 = 3008, y1 = 3450, x2 = 3020, y2 = 3462, map = 1, name="Fisherman's Brew"};
	}
	KnownAreas["Serpent's Hold"].SubAreas["Banks"] = {}
	KnownAreas["Serpent's Hold"].SubAreas["Banks"].Squares = {
			{x1 = 2870, y1 = 3462, x2 = 2888, y2 = 3480, map = 0, name="Serpent's Hold Bank"};
			{x1 = 2870, y1 = 3462, x2 = 2888, y2 = 3480, map = 1, name="Serpent's Hold Bank"};
	}
	KnownAreas["Serpent's Hold"].SubAreas["Shops"] = {}
	KnownAreas["Serpent's Hold"].SubAreas["Shops"].Squares = {
			{x1 = 2872, y1 = 3496, x2 = 2886, y2 = 3510, map = 0, name="Silver Serpent Tailors"};
			{x1 = 2904, y1 = 3480, x2 = 2910, y2 = 3494, map = 0, name="Serpent Hold Meats"};
			{x1 = 2911, y1 = 3480, x2 = 2918, y2 = 3486, map = 0, name="Serpent Hold Meats"};
			{x1 = 2896, y1 = 3512, x2 = 2910, y2 = 3518, map = 0, name="Serpents Hold Stablery"};
			{x1 = 3022, y1 = 3463, x2 = 3038, y2 = 3478, map = 0, name="Serpents Hold Stablery"};
			{x1 = 2928, y1 = 3504, x2 = 2934, y2 = 3510, map = 0, name="Tinker of the Isle"};
			{x1 = 2936, y1 = 3496, x2 = 2942, y2 = 3510, map = 0, name="Tinker of the Isle"};
			{x1 = 2992, y1 = 3424, x2 = 2998, y2 = 3438, map = 0, name="Serpent's Hold Healer"};
			{x1 = 3008, y1 = 3424, x2 = 3022, y2 = 3438, map = 0, name="Serpents Arms"};
			{x1 = 3048, y1 = 3384, x2 = 3062, y2 = 3406, map = 0, name="Warrior's Guild"};
			{x1 = 3000, y1 = 3400, x2 = 3014, y2 = 3414, map = 0, name="Blacksmith"};
			{x1 = 3000, y1 = 3384, x2 = 3014, y2 = 3390, map = 0, name="Supplies"};
			{x1 = 3001, y1 = 3384, x2 = 3014, y2 = 3390, map = 0, name="Silver Serpent Bow"};
			{x1 = 2968, y1 = 3352, x2 = 2982, y2 = 3358, map = 0, name="Plenty O' Dough"};
			{x1 = 2936, y1 = 3344, x2 = 2966, y2 = 3366, map = 0, name="Counselor's Guild"};
			{x1 = 3000, y1 = 3352, x2 = 3006, y2 = 3358, map = 0, name="Serpent's Spell"};
			{x1 = 3008, y1 = 3352, x2 = 3014, y2 = 3358, map = 0, name="Britannian Herbs"};
			{x1 = 3024, y1 = 3344, x2 = 3038, y2 = 3358, map = 0, name="Serpent Warrior's"};
			
			{x1 = 2872, y1 = 3496, x2 = 2886, y2 = 3510, map = 1, name="Silver Serpent Tailors"};
			{x1 = 2904, y1 = 3480, x2 = 2910, y2 = 3494, map = 1, name="Serpent Hold Meats"};
			{x1 = 2911, y1 = 3480, x2 = 2918, y2 = 3486, map = 1, name="Serpent Hold Meats"};
			{x1 = 2896, y1 = 3512, x2 = 2910, y2 = 3518, map = 1, name="Serpents Hold Stablery"};
			{x1 = 3022, y1 = 3463, x2 = 3038, y2 = 3478, map = 1, name="Serpents Hold Stablery"};
			{x1 = 2928, y1 = 3504, x2 = 2934, y2 = 3510, map = 1, name="Tinker of the Isle"};
			{x1 = 2936, y1 = 3496, x2 = 2942, y2 = 3510, map = 1, name="Tinker of the Isle"};
			{x1 = 2992, y1 = 3424, x2 = 2998, y2 = 3438, map = 1, name="Serpent's Hold Healer"};
			{x1 = 3008, y1 = 3424, x2 = 3022, y2 = 3438, map = 1, name="Serpents Arms"};
			{x1 = 3048, y1 = 3384, x2 = 3062, y2 = 3406, map = 1, name="Warrior's Guild"};
			{x1 = 3000, y1 = 3400, x2 = 3014, y2 = 3414, map = 1, name="Blacksmith"};
			{x1 = 3000, y1 = 3384, x2 = 3014, y2 = 3390, map = 1, name="Supplies"};
			{x1 = 3001, y1 = 3384, x2 = 3014, y2 = 3390, map = 1, name="Silver Serpent Bow"};
			{x1 = 2968, y1 = 3352, x2 = 2982, y2 = 3358, map = 1, name="Plenty O' Dough"};
			{x1 = 2936, y1 = 3344, x2 = 2966, y2 = 3366, map = 1, name="Counselor's Guild"};
			{x1 = 3000, y1 = 3352, x2 = 3006, y2 = 3358, map = 1, name="Serpent's Spell"};
			{x1 = 3008, y1 = 3352, x2 = 3014, y2 = 3358, map = 1, name="Britannian Herbs"};
			{x1 = 3024, y1 = 3344, x2 = 3038, y2 = 3358, map = 1, name="Serpent Warrior's"};
	}
-------------------------------------------------------------------
KnownAreas["Yew"] = {}
KnownAreas["Yew"].MainAreas ={
		{x1 = 92, y1 = 656, w = 349, h = 225, map = 0};
		{x1 = 441, y1 = 746, w = 216, h = 135, map = 0};
		{x1 = 258, y1 = 881, w = 399, h = 380, map = 0};
		{x1 = 657, y1 = 922, w = 42, h = 307, map = 0};
		{x1 = 657, y1 = 806, w = 17, h = 28, map = 0};
		{x1 = 718, y1 = 874, w = 38, h = 22, map = 0};
		
		{x1 = 92, y1 = 656, w = 349, h = 225, map = 1};
		{x1 = 441, y1 = 746, w = 216, h = 135, map = 1};
		{x1 = 258, y1 = 881, w = 399, h = 380, map = 1};
		{x1 = 657, y1 = 922, w = 42, h = 307, map = 1};
		{x1 = 657, y1 = 806, w = 17, h = 28, map = 1};
		{x1 = 718, y1 = 874, w = 38, h = 22, map = 1};
}
KnownAreas["Yew"].Guarded = true
KnownAreas["Yew"].SubAreas = {}
	KnownAreas["Yew"].SubAreas["Tavern"] = {}
	KnownAreas["Yew"].SubAreas["Tavern"].Squares = {
			{x1 = 600, y1 = 808, x2 = 622, y2 = 830, map = 0, name="Abbey Innkeeper"};
			{x1 = 600, y1 = 808, x2 = 622, y2 = 830, map = 1, name="Abbey Innkeeper"};
	}
	KnownAreas["Yew"].SubAreas["Banks"] = {}
	KnownAreas["Yew"].SubAreas["Banks"].Squares = {
			{x1 = 648, y1 = 809, x2 = 670, y2 = 830, map = 0, name="Abbey Banker"};
			{x1 = 648, y1 = 809, x2 = 670, y2 = 830, map = 1, name="Abbey Banker"};
	}
	KnownAreas["Yew"].SubAreas["Shops"] = {}
	KnownAreas["Yew"].SubAreas["Shops"].Squares = {
			{x1 = 624, y1 = 816, x2 = 646, y2 = 854, map = 0, name="Empath Abbey"};
			{x1 = 608, y1 = 872, x2 = 622, y2 = 894, map = 0, name="Ye Olde Winery"};
			{x1 = 544, y1 = 812, x2 = 558, y2 = 830, map = 0, name="Yew Mill"};
			{x1 = 558, y1 = 813, x2 = 566, y2 = 822, map = 0, name="Yew Mill"};
			{x1 = 560, y1 = 808, x2 = 566, y2 = 814, map = 0, name="Yew Mill"};
			{x1 = 544, y1 = 808, x2 = 550, y2 = 814, map = 0, name="Yew Mill"};
			{x1 = 528, y1 = 960, x2 = 542, y2 = 974, map = 0, name="Healer of Yew"};
			{x1 = 512, y1 = 984, x2 = 518, y2 = 998, map = 0, name="The Tanned Hide"};
			{x1 = 528, y1 = 1008, x2 = 541, y2 = 1013, map = 0, name="Yew's Finest Cuts"};
			{x1 = 552, y1 = 984, x2 = 558, y2 = 998, map = 0, name="The Jolly Baker"};
			{x1 = 560, y1 = 1008, x2 = 574, y2 = 1014, map = 0, name="Bloody Thumb Woodworks"};
			{x1 = 560, y1 = 961, x2 = 574, y2 = 974, map = 0, name="The Sturdy Bow"};
			{x1 = 608, y1 = 976, x2 = 622, y2 = 982, map = 0, name="Counselor's Guild"};
			{x1 = 624, y1 = 1032, x2 = 638, y2 = 1038, map = 0, name="Great Oak Vassels"};
			{x1 = 632, y1 = 1040, x2 = 638, y2 = 1046, map = 0, name="Great Oak Vassels"};
			{x1 = 640, y1 = 1080, x2 = 646, y2 = 1094, map = 0, name="Deep Forest Healing"};
			{x1 = 648, y1 = 1080, x2 = 654, y2 = 1086, map = 0, name="Deep Forest Healing"};
			{x1 = 617, y1 = 1144, x2 = 630, y2 = 1150, map = 0, name="Great Oak Bowyer"};
			{x1 = 336, y1 = 872, x2 = 342, y2 = 886, map = 0, name="Court of Truth"};
			{x1 = 344, y1 = 872, x2 = 370, y2 = 902, map = 0, name="Court of Truth"};
			{x1 = 372, y1 = 896, x2 = 374, y2 = 902, map = 0, name="Court of Truth"};
			{x1 = 256, y1 = 760, x2 = 292, y2 = 782, map = 0, name="Britannia Prison"};
			{x1 = 290, y1 = 764, x2 = 300, y2 = 776, map = 0, name="Britannia Prison"};
			
			{x1 = 624, y1 = 816, x2 = 646, y2 = 854, map = 1, name="Empath Abbey"};
			{x1 = 608, y1 = 872, x2 = 622, y2 = 894, map = 1, name="Ye Olde Winery"};
			{x1 = 544, y1 = 812, x2 = 558, y2 = 830, map = 1, name="Yew Mill"};
			{x1 = 558, y1 = 813, x2 = 566, y2 = 822, map = 1, name="Yew Mill"};
			{x1 = 560, y1 = 808, x2 = 566, y2 = 814, map = 1, name="Yew Mill"};
			{x1 = 544, y1 = 808, x2 = 550, y2 = 814, map = 1, name="Yew Mill"};
			{x1 = 528, y1 = 960, x2 = 542, y2 = 974, map = 1, name="Healer of Yew"};
			{x1 = 512, y1 = 984, x2 = 518, y2 = 998, map = 1, name="The Tanned Hide"};
			{x1 = 528, y1 = 1008, x2 = 541, y2 = 1013, map = 1, name="Yew's Finest Cuts"};
			{x1 = 552, y1 = 984, x2 = 558, y2 = 998, map = 1, name="The Jolly Baker"};
			{x1 = 560, y1 = 1008, x2 = 574, y2 = 1014, map = 1, name="Bloody Thumb Woodworks"};
			{x1 = 560, y1 = 961, x2 = 574, y2 = 974, map = 1, name="The Sturdy Bow"};
			{x1 = 608, y1 = 976, x2 = 622, y2 = 982, map = 1, name="Counselor's Guild"};
			{x1 = 624, y1 = 1032, x2 = 638, y2 = 1038, map = 1, name="Great Oak Vassels"};
			{x1 = 632, y1 = 1040, x2 = 638, y2 = 1046, map = 1, name="Great Oak Vassels"};
			{x1 = 640, y1 = 1080, x2 = 646, y2 = 1094, map = 1, name="Deep Forest Healing"};
			{x1 = 648, y1 = 1080, x2 = 654, y2 = 1086, map = 1, name="Deep Forest Healing"};
			{x1 = 617, y1 = 1144, x2 = 630, y2 = 1150, map = 1, name="Great Oak Bowyer"};
			{x1 = 336, y1 = 872, x2 = 342, y2 = 886, map = 1, name="Court of Truth"};
			{x1 = 344, y1 = 872, x2 = 370, y2 = 902, map = 1, name="Court of Truth"};
			{x1 = 372, y1 = 896, x2 = 374, y2 = 902, map = 1, name="Court of Truth"};
			{x1 = 256, y1 = 760, x2 = 292, y2 = 782, map = 1, name="Britannia Prison"};
			{x1 = 290, y1 = 764, x2 = 300, y2 = 776, map = 1, name="Britannia Prison"};
	}
-------------------------------------------------------------------
KnownAreas["Jhelom"] = {}
KnownAreas["Jhelom"].MainAreas ={
		{x1 = 1303, y1 = 3670, w = 189, h = 225, map = 0};
		{x1 = 1338, y1 = 3895, w = 74, h = 28, map = 0};
		{x1 = 1338, y1 = 3895, w = 74, h = 28, map = 0};
		{x1 = 1383, y1 = 3951, w = 109, h = 94, map = 0};
		
		{x1 = 1303, y1 = 3670, w = 189, h = 225, map = 1};
		{x1 = 1338, y1 = 3895, w = 74, h = 28, map = 1};
		{x1 = 1338, y1 = 3895, w = 74, h = 28, map = 1};
		{x1 = 1383, y1 = 3951, w = 109, h = 94, map = 1};
}	
KnownAreas["Jhelom"].Guarded = true
KnownAreas["Jhelom"].SubAreas = {}
	KnownAreas["Jhelom"].SubAreas["Tavern"] = {}
	KnownAreas["Jhelom"].SubAreas["Tavern"].Squares = {
			{x1 = 1433, y1 = 3768, x2 = 1439, y2 = 3774, map = 0, name="The Horse's Head"};
			{x1 = 1440, y1 = 3768, x2 = 1462, y2 = 3782, map = 0, name="The Horse's Head"};
			{x1 = 1352, y1 = 3800, x2 = 1366, y2 = 3830, map = 0, name="The Morning Star Inn"};
			{x1 = 1368, y1 = 3808, x2 = 1374, y2 = 3822, map = 0, name="The Morning Star Inn"};
			
			{x1 = 1433, y1 = 3768, x2 = 1439, y2 = 3774, map = 1, name="The Horse's Head"};
			{x1 = 1440, y1 = 3768, x2 = 1462, y2 = 3782, map = 1, name="The Horse's Head"};
			{x1 = 1352, y1 = 3800, x2 = 1366, y2 = 3830, map = 1, name="The Morning Star Inn"};
			{x1 = 1368, y1 = 3808, x2 = 1374, y2 = 3822, map = 1, name="The Morning Star Inn"};
	}
	KnownAreas["Jhelom"].SubAreas["Banks"] = {}
	KnownAreas["Jhelom"].SubAreas["Banks"].Squares = {
			{x1 = 1312, y1 = 3768, x2 = 1318, y2 = 3782, map = 0, name="Jhelom Bank and Jeweler"};
			{x1 = 1319, y1 = 3768, x2 = 1326, y2 = 3774, map = 0, name="Jhelom Bank and Jeweler"};
			
			{x1 = 1312, y1 = 3768, x2 = 1318, y2 = 3782, map = 1, name="Jhelom Bank and Jeweler"};
			{x1 = 1319, y1 = 3768, x2 = 1326, y2 = 3774, map = 1, name="Jhelom Bank and Jeweler"};
	}
	KnownAreas["Jhelom"].SubAreas["Shops"] = {}
	KnownAreas["Jhelom"].SubAreas["Shops"].Squares = {
			{x1 = 1352, y1 = 3696, x2 = 1374, y2 = 3710, map = 0, name="Brother in Arms"};
			{x1 = 1360, y1 = 3711, x2 = 1366, y2 = 3718, map = 0, name="Brother in Arms"};
			{x1 = 1352, y1 = 3728, x2 = 1359, y2 = 3734, map = 0, name="Baker's Dozen"};
			{x1 = 1360, y1 = 3728, x2 = 1366, y2 = 3742, map = 0, name="Baker's Dozen"};
			{x1 = 1384, y1 = 3704, x2 = 1391, y2 = 3710, map = 0, name="First Defense"};
			{x1 = 1392, y1 = 3696, x2 = 1398, y2 = 3718, map = 0, name="First Defense"};
			{x1 = 1408, y1 = 3696, x2 = 1422, y2 = 3718, map = 0, name="Counselor's Guild"};
			{x1 = 1423, y1 = 3696, x2 = 1430, y2 = 3702, map = 0, name="Counselor's Guild"};
			{x1 = 1432, y1 = 3712, x2 = 1446, y2 = 3726, map = 0, name="Second Skin"};
			{x1 = 1448, y1 = 3712, x2 = 1454, y2 = 3718, map = 0, name="Second Skin"};
			{x1 = 1449, y1 = 3736, x2 = 1454, y2 = 3750, map = 0, name="Sailor's Keeper"};
			{x1 = 1455, y1 = 3736, x2 = 1462, y2 = 3742, map = 0, name="Sailor's Keeper"};
			{x1 = 1432, y1 = 3736, x2 = 1436, y2 = 3756, map = 0, name="Ocean's Treasure"};
			{x1 = 1376, y1 = 3728, x2 = 1421, y2 = 3758, map = 0, name="The Dueling Pit"};
			{x1 = 1432, y1 = 3792, x2 = 1446, y2 = 3798, map = 0, name="Needful Things"};
			{x1 = 1440, y1 = 3799, x2 = 1446, y2 = 3806, map = 0, name="Needful Things"};
			{x1 = 1424, y1 = 3816, x2 = 1438, y2 = 3822, map = 0, name="From Tree to Yew"};
			{x1 = 1432, y1 = 3823, x2 = 1438, y2 = 3830, map = 0, name="From Tree to Yew"};
			{x1 = 1472, y1 = 3848, x2 = 1478, y2 = 3870, map = 0, name="Call to Arms"};
			{x1 = 1480, y1 = 3848, x2 = 1486, y2 = 3862, map = 0, name="Call to Arms"};
			{x1 = 1448, y1 = 3848, x2 = 1462, y2 = 3862, map = 0, name="Jhelom Armory"};
			{x1 = 1440, y1 = 3848, x2 = 1446, y2 = 3854, map = 0, name="Jhelom Armory"};
			{x1 = 1424, y1 = 3872, x2 = 1446, y2 = 3886, map = 0, name="Hand of Death"};
			{x1 = 1432, y1 = 3865, x2 = 1438, y2 = 3871, map = 0, name="Hand of Death"};
			{x1 = 1408, y1 = 3848, x2 = 1430, y2 = 3854, map = 0, name="Warrior's Bounty"};
			{x1 = 1416, y1 = 3855, x2 = 1422, y2 = 3862, map = 0, name="Warrior's Bounty"};
			{x1 = 1384, y1 = 3824, x2 = 1398, y2 = 3830, map = 0, name="Farmer's Market"};
			{x1 = 1392, y1 = 3800, x2 = 1406, y2 = 3814, map = 0, name="Gadgets and Things"};
			{x1 = 1408, y1 = 3800, x2 = 1414, y2 = 3806, map = 0, name="Gadgets and Things"};
			{x1 = 1344, y1 = 3776, x2 = 1366, y2 = 3782, map = 0, name="Adventurer's Needle"};
			{x1 = 1352, y1 = 3783, x2 = 1358, y2 = 3790, map = 0, name="Adventurer's Needle"};
			{x1 = 1376, y1 = 3768, x2 = 1390, y2 = 3782, map = 0, name="Jhelom Library"};
			{x1 = 1390, y1 = 3768, x2 = 1398, y2 = 3774, map = 0, name="Jhelom Library"};
			{x1 = 1344, y1 = 3752, x2 = 1350, y2 = 3758, map = 0, name="Deadly Intentions"};
			{x1 = 1352, y1 = 3752, x2 = 1366, y2 = 3766, map = 0, name="Deadly Intentions"};
			{x1 = 1448, y1 = 4024, x2 = 1462, y2 = 4030, map = 0, name="Finest Cuts"};
			{x1 = 1448, y1 = 4000, x2 = 1462, y2 = 4006, map = 0, name="Jhelom's Fine Tailoring"};
			{x1 = 1448, y1 = 4008, x2 = 1454, y2 = 4014, map = 0, name="Jhelom's Fine Tailoring"};
			{x1 = 1440, y1 = 3983, x2 = 1446, y2 = 3990, map = 0, name="The Pearl of Jhelom"};
			{x1 = 1440, y1 = 3976, x2 = 1454, y2 = 3982, map = 0, name="The Pearl of Jhelom"};
			{x1 = 1416, y1 = 3976, x2 = 1423, y2 = 3982, map = 0, name="Jhelom Mage"};
			{x1 = 1424, y1 = 3976, x2 = 1430, y2 = 3990, map = 0, name="Jhelom Mage"};
			{x1 = 1409, y1 = 4008, x2 = 1438, y2 = 4013, map = 0, name="Performing Arts Center"};
			{x1 = 1416, y1 = 4000, x2 = 1430, y2 = 4022, map = 0, name="Performing Arts Center"};
			
			{x1 = 1352, y1 = 3696, x2 = 1374, y2 = 3710, map = 1, name="Brother in Arms"};
			{x1 = 1360, y1 = 3711, x2 = 1366, y2 = 3718, map = 1, name="Brother in Arms"};
			{x1 = 1352, y1 = 3728, x2 = 1359, y2 = 3734, map = 1, name="Baker's Dozen"};
			{x1 = 1360, y1 = 3728, x2 = 1366, y2 = 3742, map = 1, name="Baker's Dozen"};
			{x1 = 1384, y1 = 3704, x2 = 1391, y2 = 3710, map = 1, name="First Defense"};
			{x1 = 1392, y1 = 3696, x2 = 1398, y2 = 3718, map = 1, name="First Defense"};
			{x1 = 1408, y1 = 3696, x2 = 1422, y2 = 3718, map = 1, name="Counselor's Guild"};
			{x1 = 1423, y1 = 3696, x2 = 1430, y2 = 3702, map = 1, name="Counselor's Guild"};
			{x1 = 1432, y1 = 3712, x2 = 1446, y2 = 3726, map = 1, name="Second Skin"};
			{x1 = 1448, y1 = 3712, x2 = 1454, y2 = 3718, map = 1, name="Second Skin"};
			{x1 = 1449, y1 = 3736, x2 = 1454, y2 = 3750, map = 1, name="Sailor's Keeper"};
			{x1 = 1455, y1 = 3736, x2 = 1462, y2 = 3742, map = 1, name="Sailor's Keeper"};
			{x1 = 1432, y1 = 3736, x2 = 1436, y2 = 3756, map = 1, name="Ocean's Treasure"};
			{x1 = 1376, y1 = 3728, x2 = 1421, y2 = 3758, map = 1, name="The Dueling Pit"};
			{x1 = 1432, y1 = 3792, x2 = 1446, y2 = 3798, map = 1, name="Needful Things"};
			{x1 = 1440, y1 = 3799, x2 = 1446, y2 = 3806, map = 1, name="Needful Things"};
			{x1 = 1424, y1 = 3816, x2 = 1438, y2 = 3822, map = 1, name="From Tree to Yew"};
			{x1 = 1432, y1 = 3823, x2 = 1438, y2 = 3830, map = 1, name="From Tree to Yew"};
			{x1 = 1472, y1 = 3848, x2 = 1478, y2 = 3870, map = 1, name="Call to Arms"};
			{x1 = 1480, y1 = 3848, x2 = 1486, y2 = 3862, map = 1, name="Call to Arms"};
			{x1 = 1448, y1 = 3848, x2 = 1462, y2 = 3862, map = 1, name="Jhelom Armory"};
			{x1 = 1440, y1 = 3848, x2 = 1446, y2 = 3854, map = 1, name="Jhelom Armory"};
			{x1 = 1424, y1 = 3872, x2 = 1446, y2 = 3886, map = 1, name="Hand of Death"};
			{x1 = 1432, y1 = 3865, x2 = 1438, y2 = 3871, map = 1, name="Hand of Death"};
			{x1 = 1408, y1 = 3848, x2 = 1430, y2 = 3854, map = 1, name="Warrior's Bounty"};
			{x1 = 1416, y1 = 3855, x2 = 1422, y2 = 3862, map = 1, name="Warrior's Bounty"};
			{x1 = 1384, y1 = 3824, x2 = 1398, y2 = 3830, map = 1, name="Farmer's Market"};
			{x1 = 1392, y1 = 3800, x2 = 1406, y2 = 3814, map = 1, name="Gadgets and Things"};
			{x1 = 1408, y1 = 3800, x2 = 1414, y2 = 3806, map = 1, name="Gadgets and Things"};
			{x1 = 1344, y1 = 3776, x2 = 1366, y2 = 3782, map = 1, name="Adventurer's Needle"};
			{x1 = 1352, y1 = 3783, x2 = 1358, y2 = 3790, map = 1, name="Adventurer's Needle"};
			{x1 = 1376, y1 = 3768, x2 = 1390, y2 = 3782, map = 1, name="Jhelom Library"};
			{x1 = 1390, y1 = 3768, x2 = 1398, y2 = 3774, map = 1, name="Jhelom Library"};
			{x1 = 1344, y1 = 3752, x2 = 1350, y2 = 3758, map = 1, name="Deadly Intentions"};
			{x1 = 1352, y1 = 3752, x2 = 1366, y2 = 3766, map = 1, name="Deadly Intentions"};
			{x1 = 1448, y1 = 4024, x2 = 1462, y2 = 4030, map = 1, name="Finest Cuts"};
			{x1 = 1448, y1 = 4000, x2 = 1462, y2 = 4006, map = 1, name="Jhelom's Fine Tailoring"};
			{x1 = 1448, y1 = 4008, x2 = 1454, y2 = 4014, map = 1, name="Jhelom's Fine Tailoring"};
			{x1 = 1440, y1 = 3983, x2 = 1446, y2 = 3990, map = 1, name="The Pearl of Jhelom"};
			{x1 = 1440, y1 = 3976, x2 = 1454, y2 = 3982, map = 1, name="The Pearl of Jhelom"};
			{x1 = 1416, y1 = 3976, x2 = 1423, y2 = 3982, map = 1, name="Jhelom Mage"};
			{x1 = 1424, y1 = 3976, x2 = 1430, y2 = 3990, map = 1, name="Jhelom Mage"};
			{x1 = 1409, y1 = 4008, x2 = 1438, y2 = 4013, map = 1, name="Performing Arts Center"};
			{x1 = 1416, y1 = 4000, x2 = 1430, y2 = 4022, map = 1, name="Performing Arts Center"};
	}
-------------------------------------------------------------------
KnownAreas["Minoc"] = {}
KnownAreas["Minoc"].MainAreas ={
		{x1 = 2411, y1 = 366, w = 135, h = 241, map = 0};
		{x1 = 2548, y1 = 495, w = 72, h = 55, map = 0};
		{x1 = 2564, y1 = 585, w = 3, h = 42, map = 0};
		{x1 = 2567, y1 = 585, w = 61, h = 61, map = 0};
		{x1 = 2499, y1 = 627, w = 68, h = 63, map = 0};
		
		{x1 = 2411, y1 = 366, w = 135, h = 241, map = 1};
		{x1 = 2548, y1 = 495, w = 72, h = 55, map = 1};
		{x1 = 2564, y1 = 585, w = 3, h = 42, map = 1};
		{x1 = 2567, y1 = 585, w = 61, h = 61, map = 1};
		{x1 = 2499, y1 = 627, w = 68, h = 63, map = 1};
}	
KnownAreas["Minoc"].Guarded = true
KnownAreas["Minoc"].SubAreas = {}
	KnownAreas["Minoc"].SubAreas["Tavern"] = {}
	KnownAreas["Minoc"].SubAreas["Tavern"].Squares = {
			{x1 = 2457, y1 = 397, x2 = 2495, y2 = 403, map = 0, name="The Barnacle"};
			{x1 = 2481, y1 = 405, x2 = 2487, y2 = 411, map = 0, name="The Barnacle"};
			{x1 = 2465, y1 = 405, x2 = 2471, y2 = 411, map = 0, name="The Barnacle"};
			
			{x1 = 2457, y1 = 397, x2 = 2495, y2 = 403, map = 1, name="The Barnacle"};
			{x1 = 2481, y1 = 405, x2 = 2487, y2 = 411, map = 1, name="The Barnacle"};
			{x1 = 2465, y1 = 405, x2 = 2471, y2 = 411, map = 1, name="The Barnacle"};
	}
	KnownAreas["Minoc"].SubAreas["Banks"] = {}
	KnownAreas["Minoc"].SubAreas["Banks"].Squares = {
			{x1 = 2496, y1 = 544, x2 = 2510, y2 = 558, map = 0, name="Bank of Minoc"};
			{x1 = 2496, y1 = 544, x2 = 2510, y2 = 558, map = 1, name="Bank of Minoc"};
	}
	KnownAreas["Minoc"].SubAreas["Shops"] = {}
	KnownAreas["Minoc"].SubAreas["Shops"].Squares = {
			{x1 = 2570, y1 = 587, x2 = 2576, y2 = 601, map = 0, name="The Healing Hand"};
			{x1 = 2577, y1 = 595, x2 = 2584, y2 = 601, map = 0, name="The Healing Hand"};
			{x1 = 2499, y1 = 627, w = 68, h = 63, map = 0, name="Gipsy Camp"};
			{x1 = 2522, y1 = 570, x2 = 2536, y2 = 576, map = 0, name="Warriors' Battle Gear"};
			{x1 = 2530, y1 = 578, x2 = 2536, y2 = 584, map = 0, name="Warriors' Battle Gear"};
			{x1 = 2520, y1 = 544, x2 = 2527, y2 = 550, map = 0, name="The Survival Shop"};
			{x1 = 2528, y1 = 544, x2 = 2534, y2 = 558, map = 0, name="The Survival Shop"};
			{x1 = 2465, y1 = 554, x2 = 2471, y2 = 567, map = 0, name="The Forgery"};
			{x1 = 2472, y1 = 561, x2 = 2479, y2 = 567, map = 0, name="The Forgery"};
			{x1 = 2512, y1 = 520, x2 = 2519, y2 = 526, map = 0, name="The Stretched Hide"};	
			{x1 = 2520, y1 = 520, x2 = 2526, y2 = 534, map = 0, name="The Stretched Hide"};		
			{x1 = 2417, y1 = 544, x2 = 2422, y2 = 558, map = 0, name="The Mystical Lute"};
			{x1 = 2423, y1 = 552, x2 = 2430, y2 = 558, map = 0, name="The Mystical Lute"};
			{x1 = 2416, y1 = 523, x2 = 2438, y2 = 534, map = 0, name="Minoc Town Hall"};
			{x1 = 2443, y1 = 483, x2 = 2465, y2 = 489, map = 0, name="The Matewan"};
			{x1 = 2451, y1 = 475, x2 = 2457, y2 = 497, map = 0, name="The Matewan"};
			{x1 = 2450, y1 = 450, x2 = 2472, y2 = 456, map = 0, name="Gears and Gadgets"};
			{x1 = 2458, y1 = 457, x2 = 2464, y2 = 464, map = 0, name="Gears and Gadgets"};
			{x1 = 2506, y1 = 467, x2 = 2512, y2 = 473, map = 0, name="The Oak Throne"};
			{x1 = 2506, y1 = 474, x2 = 2520, y2 = 480, map = 0, name="The Oak Throne"};
			{x1 = 2496, y1 = 424, x2 = 2499, y2 = 438, map = 0, name="The Golden Pick Axe"};
			{x1 = 2506, y1 = 424, x2 = 2510, y2 = 438, map = 0, name="The Golden Pick Axe"};
			{x1 = 2500, y1 = 424, x2 = 2506, y2 = 433, map = 0, name="The Golden Pick Axe"};
			{x1 = 2472, y1 = 424, x2 = 2479, y2 = 430, map = 0, name="The New World Order"};
			{x1 = 2479, y1 = 424, x2 = 2486, y2 = 438, map = 0, name="The New World Order"};
			{x1 = 2448, y1 = 432, x2 = 2454, y2 = 438, map = 0, name="The Old Miners' Supplies"};
			{x1 = 2448, y1 = 424, x2 = 2462, y2 = 430, map = 0, name="The Old Miners' Supplies"};
			{x1 = 2427, y1 = 427, x2 = 2433, y2 = 433, map = 0, name="Counselor's Guild"};
			{x1 = 2427, y1 = 435, x2 = 2441, y2 = 441, map = 0, name="Counselor's Guild"};
			{x1 = 2432, y1 = 400, x2 = 2438, y2 = 406, map = 0, name="The Slaughtered Cow"};
			{x1 = 2432, y1 = 408, x2 = 2446, y2 = 414, map = 0, name="The Slaughtered Cow"};
			{x1 = 2515, y1 = 371, x2 = 2537, y2 = 377, map = 0, name="Stables"};
			
			{x1 = 2570, y1 = 587, x2 = 2576, y2 = 601, map = 1, name="The Healing Hand"};
			{x1 = 2577, y1 = 595, x2 = 2584, y2 = 601, map = 1, name="The Healing Hand"};
			{x1 = 2499, y1 = 627, w = 68, h = 63, map = 1, name="Gipsy Camp"};
			{x1 = 2522, y1 = 570, x2 = 2536, y2 = 576, map = 1, name="Warriors' Battle Gear"};
			{x1 = 2530, y1 = 578, x2 = 2536, y2 = 584, map = 1, name="Warriors' Battle Gear"};
			{x1 = 2520, y1 = 544, x2 = 2527, y2 = 550, map = 1, name="The Survival Shop"};
			{x1 = 2528, y1 = 544, x2 = 2534, y2 = 558, map = 1, name="The Survival Shop"};
			{x1 = 2465, y1 = 554, x2 = 2471, y2 = 567, map = 1, name="The Forgery"};
			{x1 = 2472, y1 = 561, x2 = 2479, y2 = 567, map = 1, name="The Forgery"};
			{x1 = 2512, y1 = 520, x2 = 2519, y2 = 526, map = 1, name="The Stretched Hide"};	
			{x1 = 2520, y1 = 520, x2 = 2526, y2 = 534, map = 1, name="The Stretched Hide"};		
			{x1 = 2417, y1 = 544, x2 = 2422, y2 = 558, map = 1, name="The Mystical Lute"};
			{x1 = 2423, y1 = 552, x2 = 2430, y2 = 558, map = 1, name="The Mystical Lute"};
			{x1 = 2416, y1 = 523, x2 = 2438, y2 = 534, map = 1, name="Minoc Town Hall"};
			{x1 = 2443, y1 = 483, x2 = 2465, y2 = 489, map = 1, name="The Matewan"};
			{x1 = 2451, y1 = 475, x2 = 2457, y2 = 497, map = 1, name="The Matewan"};
			{x1 = 2450, y1 = 450, x2 = 2472, y2 = 456, map = 1, name="Gears and Gadgets"};
			{x1 = 2458, y1 = 457, x2 = 2464, y2 = 464, map = 1, name="Gears and Gadgets"};
			{x1 = 2506, y1 = 467, x2 = 2512, y2 = 473, map = 1, name="The Oak Throne"};
			{x1 = 2506, y1 = 474, x2 = 2520, y2 = 480, map = 1, name="The Oak Throne"};
			{x1 = 2496, y1 = 424, x2 = 2499, y2 = 438, map = 1, name="The Golden Pick Axe"};
			{x1 = 2506, y1 = 424, x2 = 2510, y2 = 438, map = 1, name="The Golden Pick Axe"};
			{x1 = 2500, y1 = 424, x2 = 2506, y2 = 433, map = 1, name="The Golden Pick Axe"};
			{x1 = 2472, y1 = 424, x2 = 2479, y2 = 430, map = 1, name="The New World Order"};
			{x1 = 2479, y1 = 424, x2 = 2486, y2 = 438, map = 1, name="The New World Order"};
			{x1 = 2448, y1 = 432, x2 = 2454, y2 = 438, map = 1, name="The Old Miners' Supplies"};
			{x1 = 2448, y1 = 424, x2 = 2462, y2 = 430, map = 1, name="The Old Miners' Supplies"};
			{x1 = 2427, y1 = 427, x2 = 2433, y2 = 433, map = 1, name="Counselor's Guild"};
			{x1 = 2427, y1 = 435, x2 = 2441, y2 = 441, map = 1, name="Counselor's Guild"};
			{x1 = 2432, y1 = 400, x2 = 2438, y2 = 406, map = 1, name="The Slaughtered Cow"};
			{x1 = 2432, y1 = 408, x2 = 2446, y2 = 414, map = 1, name="The Slaughtered Cow"};
			{x1 = 2515, y1 = 371, x2 = 2537, y2 = 377, map = 1, name="Stables"};
	}
-------------------------------------------------------------------
KnownAreas["Skara Brae"] = {}
KnownAreas["Skara Brae"].MainAreas ={
		{x1 = 538, y1 = 2107, w = 150, h = 190, map = 0};
		{x1 = 538, y1 = 2107, w = 150, h = 190, map = 1};
}	
KnownAreas["Skara Brae"].Guarded = true
KnownAreas["Skara Brae"].SubAreas = {}
	KnownAreas["Skara Brae"].SubAreas["Tavern"] = {}
	KnownAreas["Skara Brae"].SubAreas["Tavern"].Squares = {
			{x1 = 552, y1 = 2168, x2 = 566, y2 = 2190, map = 0, name="The Shattered Skull"};
			{x1 = 568, y1 = 2168, x2 = 574, y2 = 2174, map = 0, name="The Shattered Skull"};
			{x1 = 592, y1 = 2240, x2 = 622, y2 = 2254, map = 0, name="The Falconer's Inn"};
			{x1 = 600, y1 = 2232, x2 = 614, y2 = 2238, map = 0, name="The Falconer's Inn"};
			
			{x1 = 552, y1 = 2168, x2 = 566, y2 = 2190, map = 1, name="The Shattered Skull"};
			{x1 = 568, y1 = 2168, x2 = 574, y2 = 2174, map = 1, name="The Shattered Skull"};
			{x1 = 592, y1 = 2240, x2 = 622, y2 = 2254, map = 1, name="The Falconer's Inn"};
			{x1 = 600, y1 = 2232, x2 = 614, y2 = 2238, map = 1, name="The Falconer's Inn"};
	}
	KnownAreas["Skara Brae"].SubAreas["Banks"] = {}
	KnownAreas["Skara Brae"].SubAreas["Banks"].Squares = {
			{x1 = 584, y1 = 2136, x2 = 590, y2 = 2142, map = 0, name="Bank of Skara Brae"};
			{x1 = 584, y1 = 2144, x2 = 598, y2 = 2150, map = 0, name="Bank of Skara Brae"};
			
			{x1 = 584, y1 = 2136, x2 = 590, y2 = 2142, map = 1, name="Bank of Skara Brae"};
			{x1 = 584, y1 = 2144, x2 = 598, y2 = 2150, map = 1, name="Bank of Skara Brae"};
	}
	KnownAreas["Skara Brae"].SubAreas["Shops"] = {}
	KnownAreas["Skara Brae"].SubAreas["Shops"].Squares = {
			{x1 = 608, y1 = 2120, x2 = 630, y2 = 2134, map = 0, name="Counselor's Guild"};
			{x1 = 616, y1 = 2112, x2 = 622, y2 = 2119, map = 0, name="Counselor's Guild"};
			{x1 = 616, y1 = 2136, x2 = 622, y2 = 2142, map = 0, name="Counselor's Guild"};
			{x1 = 568, y1 = 2112, x2 = 574, y2 = 2118, map = 0, name="Beasts of Burden"};
			{x1 = 568, y1 = 2120, x2 = 582, y2 = 2126, map = 0, name="Beasts of Burden"};
			{x1 = 552, y1 = 2136, x2 = 566, y2 = 2158, map = 0, name="Rangers' Guild"};
			{x1 = 567, y1 = 2144, x2 = 574, y2 = 2150, map = 0, name="Rangers' Guild"};
			{x1 = 608, y1 = 2152, x2 = 614, y2 = 2166, map = 0, name="Farmers' Market"};
			{x1 = 656, y1 = 2136, x2 = 670, y2 = 2142, map = 0, name="Mystic Treasures"};
			{x1 = 664, y1 = 2144, x2 = 670, y2 = 2150, map = 0, name="Mystic Treasures"};
			{x1 = 648, y1 = 2152, x2 = 654, y2 = 2158, map = 0, name="Gore Galore"};
			{x1 = 648, y1 = 2160, x2 = 662, y2 = 2166, map = 0, name="Gore Galore"};
			{x1 = 624, y1 = 2152, x2 = 638, y2 = 2166, map = 0, name="Builder's Delight"};
			{x1 = 624, y1 = 2168, x2 = 630, y2 = 2174, map = 0, name="Builder's Delight"};
			{x1 = 584, y1 = 2160, x2 = 590, y2 = 2174, map = 0, name="More Than Just Mail"};
			{x1 = 592, y1 = 2160, x2 = 598, y2 = 2166, map = 0, name="More Than Just Mail"};
			{x1 = 576, y1 = 2184, x2 = 590, y2 = 2190, map = 0, name="Bointful Meats"};
			{x1 = 600, y1 = 2176, x2 = 614, y2 = 2182, map = 0, name="Mages' Menagerie"};
			{x1 = 600, y1 = 2184, x2 = 606, y2 = 2190, map = 0, name="Mages' Menagerie"};
			{x1 = 640, y1 = 2176, x2 = 646, y2 = 2182, map = 0, name="Shear Pleasure"};
			{x1 = 648, y1 = 2176, x2 = 654, y2 = 2190, map = 0, name="Shear Pleasure"};
			{x1 = 616, y1 = 2192, x2 = 638, y2 = 2198, map = 0, name="On Guard Armory"};
			{x1 = 624, y1 = 2184, x2 = 630, y2 = 2191, map = 0, name="On Guard Armory"};
			{x1 = 584, y1 = 2200, x2 = 598, y2 = 2214, map = 0, name="Bloody Bowman"};
			{x1 = 600, y1 = 2200, x2 = 606, y2 = 2206, map = 0, name="Bloody Bowman"};
			{x1 = 544, y1 = 2208, x2 = 574, y2 = 2214, map = 0, name="Skara Brae Town Hall"};
			{x1 = 553, y1 = 2200, x2 = 566, y2 = 2222, map = 0, name="Skara Brae Town Hall"};
			{x1 = 576, y1 = 2224, x2 = 590, y2 = 2230, map = 0, name="Sundry Supplies"};
			{x1 = 576, y1 = 2232, x2 = 582, y2 = 2238, map = 0, name="Sundry Supplies"};
			{x1 = 616, y1 = 2208, x2 = 630, y2 = 2222, map = 0, name="Healer of Skara Brae"};
			{x1 = 608, y1 = 2216, x2 = 614, y2 = 2222, map = 0, name="Healer of Skara Brae"};
			{x1 = 592, y1 = 2272, x2 = 598, y2 = 2278, map = 0, name="Superior Ships"};
			{x1 = 600, y1 = 2272, x2 = 606, y2 = 2286, map = 0, name="Superior Ships"};
			
			{x1 = 608, y1 = 2120, x2 = 630, y2 = 2134, map = 1, name="Counselor's Guild"};
			{x1 = 616, y1 = 2112, x2 = 622, y2 = 2119, map = 1, name="Counselor's Guild"};
			{x1 = 616, y1 = 2136, x2 = 622, y2 = 2142, map = 1, name="Counselor's Guild"};
			{x1 = 568, y1 = 2112, x2 = 574, y2 = 2118, map = 1, name="Beasts of Burden"};
			{x1 = 568, y1 = 2120, x2 = 582, y2 = 2126, map = 1, name="Beasts of Burden"};
			{x1 = 552, y1 = 2136, x2 = 566, y2 = 2158, map = 1, name="Rangers' Guild"};
			{x1 = 567, y1 = 2144, x2 = 574, y2 = 2150, map = 1, name="Rangers' Guild"};
			{x1 = 608, y1 = 2152, x2 = 614, y2 = 2166, map = 1, name="Farmers' Market"};
			{x1 = 656, y1 = 2136, x2 = 670, y2 = 2142, map = 1, name="Mystic Treasures"};
			{x1 = 664, y1 = 2144, x2 = 670, y2 = 2150, map = 1, name="Mystic Treasures"};
			{x1 = 648, y1 = 2152, x2 = 654, y2 = 2158, map = 1, name="Gore Galore"};
			{x1 = 648, y1 = 2160, x2 = 662, y2 = 2166, map = 1, name="Gore Galore"};
			{x1 = 624, y1 = 2152, x2 = 638, y2 = 2166, map = 1, name="Builder's Delight"};
			{x1 = 624, y1 = 2168, x2 = 630, y2 = 2174, map = 1, name="Builder's Delight"};
			{x1 = 584, y1 = 2160, x2 = 590, y2 = 2174, map = 1, name="More Than Just Mail"};
			{x1 = 592, y1 = 2160, x2 = 598, y2 = 2166, map = 1, name="More Than Just Mail"};
			{x1 = 576, y1 = 2184, x2 = 590, y2 = 2190, map = 1, name="Bointful Meats"};
			{x1 = 600, y1 = 2176, x2 = 614, y2 = 2182, map = 1, name="Mages' Menagerie"};
			{x1 = 600, y1 = 2184, x2 = 606, y2 = 2190, map = 1, name="Mages' Menagerie"};
			{x1 = 640, y1 = 2176, x2 = 646, y2 = 2182, map = 1, name="Shear Pleasure"};
			{x1 = 648, y1 = 2176, x2 = 654, y2 = 2190, map = 1, name="Shear Pleasure"};
			{x1 = 616, y1 = 2192, x2 = 638, y2 = 2198, map = 1, name="On Guard Armory"};
			{x1 = 624, y1 = 2184, x2 = 630, y2 = 2191, map = 1, name="On Guard Armory"};
			{x1 = 584, y1 = 2200, x2 = 598, y2 = 2214, map = 1, name="Bloody Bowman"};
			{x1 = 600, y1 = 2200, x2 = 606, y2 = 2206, map = 1, name="Bloody Bowman"};
			{x1 = 544, y1 = 2208, x2 = 574, y2 = 2214, map = 1, name="Skara Brae Town Hall"};
			{x1 = 553, y1 = 2200, x2 = 566, y2 = 2222, map = 1, name="Skara Brae Town Hall"};
			{x1 = 576, y1 = 2224, x2 = 590, y2 = 2230, map = 1, name="Sundry Supplies"};
			{x1 = 576, y1 = 2232, x2 = 582, y2 = 2238, map = 1, name="Sundry Supplies"};
			{x1 = 616, y1 = 2208, x2 = 630, y2 = 2222, map = 1, name="Healer of Skara Brae"};
			{x1 = 608, y1 = 2216, x2 = 614, y2 = 2222, map = 1, name="Healer of Skara Brae"};
			{x1 = 592, y1 = 2272, x2 = 598, y2 = 2278, map = 1, name="Superior Ships"};
			{x1 = 600, y1 = 2272, x2 = 606, y2 = 2286, map = 1, name="Superior Ships"};
	}
-------------------------------------------------------------------
KnownAreas["Trinsic"] = {}
KnownAreas["Trinsic"].MainAreas ={
		{x1 = 1856, y1 = 2636, w = 75, h = 28, map = 0};
		{x1 = 1816, y1 = 2664, w = 283, h = 231, map = 0};
		{x1 = 2099, y1 = 2782, w = 18, h = 25, map = 0};
		{x1 = 1970, y1 = 2895, w = 47, h = 32, map = 0};
		{x1 = 1796, y1 = 2696, w = 20, h = 67, map = 0};
		{x1 = 1800, y1 = 2796, w = 16, h = 52, map = 0};
		
		{x1 = 1856, y1 = 2636, w = 75, h = 28, map = 1};
		{x1 = 1816, y1 = 2664, w = 283, h = 231, map = 1};
		{x1 = 2099, y1 = 2782, w = 18, h = 25, map = 1};
		{x1 = 1970, y1 = 2895, w = 47, h = 32, map = 1};
		{x1 = 1796, y1 = 2696, w = 20, h = 67, map = 1};
		{x1 = 1800, y1 = 2796, w = 16, h = 52, map = 1};
}	
KnownAreas["Trinsic"].Guarded = true
KnownAreas["Trinsic"].SubAreas = {}
	KnownAreas["Trinsic"].SubAreas["Tavern"] = {}
	KnownAreas["Trinsic"].SubAreas["Tavern"].Squares = {
			{x1 = 2024, y1 = 2784, x2 = 2038, y2 = 2811, map = 0, name="The Rusty Anchor"};
			{x1 = 1925, y1 = 2786, x2 = 1940, y2 = 2798, map = 0, name="The Keg and Anchor"};
			{x1 = 1923, y1 = 2804, x2 = 1933, y2 = 2800, map = 0, name="The Keg and Anchor"};
			{x1 = 1834, y1 = 2728, x2 = 1854, y2 = 2742, map = 0, name="The Travellers Inn"};
			
			{x1 = 2024, y1 = 2784, x2 = 2038, y2 = 2811, map = 1, name="The Rusty Anchor"};
			{x1 = 1925, y1 = 2786, x2 = 1940, y2 = 2798, map = 1, name="The Keg and Anchor"};
			{x1 = 1923, y1 = 2804, x2 = 1933, y2 = 2800, map = 1, name="The Keg and Anchor"};
			{x1 = 1834, y1 = 2728, x2 = 1854, y2 = 2742, map = 1, name="The Travellers Inn"};
	}
	KnownAreas["Trinsic"].SubAreas["Banks"] = {}
	KnownAreas["Trinsic"].SubAreas["Banks"].Squares = {
			{x1 = 1809, y1 = 2819, x2 = 1818, y2 = 2838, map = 0, name="Bank of Britannia: Trinsic Branch"};
			{x1 = 1888, y1 = 2680, x2 = 1902, y2 = 2694, map = 0, name="Trinsic Royal Bank"};
			{x1 = 1880, y1 = 2688, x2 = 1891, y2 = 2694, map = 0, name="Trinsic Royal Bank"};
			
			{x1 = 1809, y1 = 2819, x2 = 1818, y2 = 2838, map = 1, name="Bank of Britannia: Trinsic Branch"};
			{x1 = 1888, y1 = 2680, x2 = 1902, y2 = 2694, map = 1, name="Trinsic Royal Bank"};
			{x1 = 1880, y1 = 2688, x2 = 1891, y2 = 2694, map = 1, name="Trinsic Royal Bank"};
	}
	KnownAreas["Trinsic"].SubAreas["Shops"] = {}
	KnownAreas["Trinsic"].SubAreas["Shops"].Squares = {
			{x1 = 1985, y1 = 2879, x2 = 1993, y2 = 2900, map = 0, name="The Trinsic Cut"};
			{x1 = 1991, y1 = 2879, x2 = 1998, y2 = 2891, map = 0, name="The Trinsic Cut"};
			{x1 = 2020, y1 = 2832, x2 = 2035, y2 = 2854, map = 0, name="Sons of the Sea"};
			{x1 = 2020, y1 = 2856, x2 = 2030, y2 = 2868, map = 0, name="Sons of the Sea"};
			{x1 = 1985, y1 = 2858, x2 = 1995, y2 = 2875, map = 0, name="Trinsic Fine Skins"};
			{x1 = 1976, y1 = 2829, x2 = 1985, y2 = 2844, map = 0, name="Adventurer's Clothing"};
			{x1 = 1986, y1 = 2837, x2 = 1991, y2 = 2844, map = 0, name="Adventurer's Clothing"};
			{x1 = 2006, y1 = 2800, x2 = 2022, y2 = 2811, map = 0, name="First Trinsic Stablery"};
			{x1 = 1906, y1 = 2802, x2 = 1921, y2 = 2811, map = 0, name="Trinsic Healer"};
			{x1 = 1891, y1 = 2802, x2 = 1904, y2 = 2812, map = 0, name="The Pearl of Trinsic"};
			{x1 = 1877, y1 = 2800, x2 = 1889, y2 = 2812, map = 0, name="Baked Delights"};
			{x1 = 1882, y1 = 2827, x2 = 1900, y2 = 2840, map = 0, name="Counselor's Guild"};
			{x1 = 1902, y1 = 2834, x2 = 1908, y2 = 2844, map = 0, name="Counselor's Guild"};
			{x1 = 1874, y1 = 2834, x2 = 1880, y2 = 2844, map = 0, name="Counselor's Guild"};
			{x1 = 1844, y1 = 2786, x2 = 1860, y2 = 2798, map = 0, name="Britannia Provisions"};
			{x1 = 1843, y1 = 2756, x2 = 1861, y2 = 2774, map = 0, name="Jail"};
			{x1 = 1818, y1 = 2730, x2 = 1826, y2 = 2742, map = 0, name="Trinsic Stablery"};
			{x1 = 1837, y1 = 2701, x2 = 1850, y2 = 2718, map = 0, name="Encyclopedia Magicka"};
			{x1 = 1838, y1 = 2673, x2 = 1861, y2 = 2686, map = 0, name="Tinkers Guild"};
			{x1 = 1884, y1 = 2644, x2 = 1907, y2 = 2658, map = 0, name="Shining Path Armory"};
			{x1 = 1876, y1 = 2701, x2 = 1910, y2 = 2738, map = 0, name="Meeting Hall"};
			{x1 = 1934, y1 = 2758, x2 = 1943, y2 = 2774, map = 0, name="Honorable Arms"};
			{x1 = 1943, y1 = 2758, x2 = 1948, y2 = 2770, map = 0, name="Honorable Arms"};
			{x1 = 1932, y1 = 2722, x2 = 1942, y2 = 2750, map = 0, name="Brotherhood of Trinsic"};
			{x1 = 1932, y1 = 2683, x2 = 1966, y2 = 2693, map = 0, name="Barracks"};
			{x1 = 1932, y1 = 2699, x2 = 1942, y2 = 2714, map = 0, name="Barracks"};
			{x1 = 1992, y1 = 2715, x2 = 2013, y2 = 2722, map = 0, name="Paladin's Library"};
			{x1 = 1996, y1 = 2720, x2 = 2009, y2 = 2726, map = 0, name="Paladin's Library"};
			{x1 = 2024, y1 = 2736, x2 = 2038, y2 = 2750, map = 0, name="Trinsic Training Hall"};
			{x1 = 2015, y1 = 2743, x2 = 2023, y2 = 2751, map = 0, name="Trinsic Training Hall"};
			
			{x1 = 1985, y1 = 2879, x2 = 1993, y2 = 2900, map = 1, name="The Trinsic Cut"};
			{x1 = 1991, y1 = 2879, x2 = 1998, y2 = 2891, map = 1, name="The Trinsic Cut"};
			{x1 = 2020, y1 = 2832, x2 = 2035, y2 = 2854, map = 1, name="Sons of the Sea"};
			{x1 = 2020, y1 = 2856, x2 = 2030, y2 = 2868, map = 1, name="Sons of the Sea"};
			{x1 = 1985, y1 = 2858, x2 = 1995, y2 = 2875, map = 1, name="Trinsic Fine Skins"};
			{x1 = 1976, y1 = 2829, x2 = 1985, y2 = 2844, map = 1, name="Adventurer's Clothing"};
			{x1 = 1986, y1 = 2837, x2 = 1991, y2 = 2844, map = 1, name="Adventurer's Clothing"};
			{x1 = 2006, y1 = 2800, x2 = 2022, y2 = 2811, map = 1, name="First Trinsic Stablery"};
			{x1 = 1906, y1 = 2802, x2 = 1921, y2 = 2811, map = 1, name="Trinsic Healer"};
			{x1 = 1891, y1 = 2802, x2 = 1904, y2 = 2812, map = 1, name="The Pearl of Trinsic"};
			{x1 = 1877, y1 = 2800, x2 = 1889, y2 = 2812, map = 1, name="Baked Delights"};
			{x1 = 1882, y1 = 2827, x2 = 1900, y2 = 2840, map = 1, name="Counselor's Guild"};
			{x1 = 1902, y1 = 2834, x2 = 1908, y2 = 2844, map = 1, name="Counselor's Guild"};
			{x1 = 1874, y1 = 2834, x2 = 1880, y2 = 2844, map = 1, name="Counselor's Guild"};
			{x1 = 1844, y1 = 2786, x2 = 1860, y2 = 2798, map = 1, name="Britannia Provisions"};
			{x1 = 1843, y1 = 2756, x2 = 1861, y2 = 2774, map = 1, name="Jail"};
			{x1 = 1818, y1 = 2730, x2 = 1826, y2 = 2742, map = 1, name="Trinsic Stablery"};
			{x1 = 1837, y1 = 2701, x2 = 1850, y2 = 2718, map = 1, name="Encyclopedia Magicka"};
			{x1 = 1838, y1 = 2673, x2 = 1861, y2 = 2686, map = 1, name="Tinkers Guild"};
			{x1 = 1884, y1 = 2644, x2 = 1907, y2 = 2658, map = 1, name="Shining Path Armory"};
			{x1 = 1876, y1 = 2701, x2 = 1910, y2 = 2738, map = 1, name="Meeting Hall"};
			{x1 = 1934, y1 = 2758, x2 = 1943, y2 = 2774, map = 1, name="Honorable Arms"};
			{x1 = 1943, y1 = 2758, x2 = 1948, y2 = 2770, map = 1, name="Honorable Arms"};
			{x1 = 1932, y1 = 2722, x2 = 1942, y2 = 2750, map = 1, name="Brotherhood of Trinsic"};
			{x1 = 1932, y1 = 2683, x2 = 1966, y2 = 2693, map = 1, name="Barracks"};
			{x1 = 1932, y1 = 2699, x2 = 1942, y2 = 2714, map = 1, name="Barracks"};
			{x1 = 1992, y1 = 2715, x2 = 2013, y2 = 2722, map = 1, name="Paladin's Library"};
			{x1 = 1996, y1 = 2720, x2 = 2009, y2 = 2726, map = 1, name="Paladin's Library"};
			{x1 = 2024, y1 = 2736, x2 = 2038, y2 = 2750, map = 1, name="Trinsic Training Hall"};
			{x1 = 2015, y1 = 2743, x2 = 2023, y2 = 2751, map = 1, name="Trinsic Training Hall"};
	}
-------------------------------------------------------------------

