
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------
CraftingWindow = {}
CraftingWindow.index = {}

CraftingWindow.MainGump = 460
CraftingWindow.InfoGump = 685

CraftingWindow.MaterialBase1 = 5000
CraftingWindow.MaterialBase2 = 4000

CraftingWindow.MakeLastButtonID = 1999
CraftingWindow.MakeCancelButtonID = 1998
CraftingWindow.InfoBackButtonID = 9999

CraftingWindow.EnhanceButtonID = 2000

CraftingWindow.MaterialUseColor1Toggle 	= 3000
CraftingWindow.MaterialUseColor2Toggle 	= 3001

CraftingWindow.MarkButtonID 		= 6000  --  If sent, show mark toggle
CraftingWindow.MarkItemButtonToggle 	= 6001 	--  If sent, set mark toggle
CraftingWindow.QuestMarkButtonToggle 	= 6002 	--  If sent, set quest mark toggle
CraftingWindow.MakeLastButtonToggle 	= 6003	--  If sent, set make last toggle
CraftingWindow.MakeOneButtonToggle 	= 6004	--  If sent, don't set make max or make num
CraftingWindow.MakeMaxButtonToggle 	= 6005	--  If sent, set make max don't set make num
CraftingWindow.MakeNumButtonToggle 	= 6100 	--  If >= 6100, set make num don't set make max and set "number to make"=val-6100
CraftingWindow.MaxMakeNum 		= 99 	--  Max number allowed in make number box
CraftingWindow.RecycleButtonID = 7000
CraftingWindow.RepairButtonID = 8000
CraftingWindow.AlterItemButtonID = 9000

CraftingWindow.numRecipes = 0
CraftingWindow.numCategories = 0

CraftingWindow.itemList = {}
CraftingWindow.numItems = 0
CraftingWindow.selectedRecipe = 0
CraftingWindow.MaterialSelection = false
CraftingWindow.CraftingType = 0
CraftingWindow.lastRecipeTID = 0

CraftingWindow.statusValues = {}

CraftingWindow.buttonFlags = {}
CraftingWindow.buttonText = {}

CraftingWindow.ActionButtonsInRow = 0

-- Used during filtering to track the recipe to which we should anchor
CraftingWindow.previousRecipe = nil

CraftingWindow.MaterialItemIndex = {
	-- all metals->ingot
	[1044022] = {objectType=7154, hue=0}, 
	[1044023] = {objectType=7154, hue=2419}, 
	[1044024] = {objectType=7154, hue=2406}, 
	[1044025] = {objectType=7154, hue=2413}, 
	[1044026] = {objectType=7154, hue=2418}, 
	[1044027] = {objectType=7154, hue=2213}, 
	[1044028] = {objectType=7154, hue=2425}, 
	[1044029] = {objectType=7154, hue=2207},
	[1044030] = {objectType=7154, hue=2219},
	[1044031] = {objectType=0, hue=0},
	-- all woods->board
	[1072643] = {objectType=7127, hue=0}, 
	[1072644] = {objectType=7127, hue=2010}, 
	[1072645] = {objectType=7127, hue=1191}, 
	[1072646] = {objectType=7127, hue=1192}, 
	[1072647] = {objectType=7127, hue=1193}, 
	[1072648] = {objectType=7127, hue=1194}, 
	[1072649] = {objectType=7127, hue=1151},
	[1072650] = {objectType=0, hue=0},
	-- all leathers->cut leather
	[1049150] = {objectType=4225, hue=0}, 
	[1049151] = {objectType=4225, hue=2220}, 
	[1049152] = {objectType=4225, hue=2117}, 
	[1049153] = {objectType=4225, hue=2129},
	[1049154] = {objectType=0, hue=0},
	-- dragon scales
	[1060875] = {objectType=9908, hue=1645}, 
	[1060876] = {objectType=9908, hue=2216}, 
	[1060877] = {objectType=9908, hue=1109}, 
	[1060878] = {objectType=9908, hue=2129}, 
	[1060879] = {objectType=9908, hue=2301}, 
	[1060880] = {objectType=9908, hue=2224},
	[1060881] = {objectType=0, hue=0},
	-- Stone (6009) is handled as a special case in the Lua code
}

CraftingWindow.firstMaterial1 = {
	0,					-- Alchemy (1)
	1044022,			-- Blacksmithing (2)
	0,					-- Cooking (3)
	1072643,			-- Carpentry (4)
	1049150,			-- Tailoring (5)
	1072643,			-- Bowcraft and Fletching (6)
	1044022,			-- Tinkering (7)
	0,					-- Cartography (8)
	0,					-- Inscription (9)
	1044022,			-- Masonry (10)
	0,					-- Glassblowing (11)
}

CraftingWindow.lastMaterial1 = {
	0,					-- Alchemy (1)
	1044030,			-- Blacksmithing (2)
	0,					-- Cooking (3)
	1072649,			-- Carpentry (4)
	1049153,			-- Tailoring (5)
	1072649,			-- Bowcraft and Fletching (6)
	1044030,			-- Tinkering (7)
	0,					-- Cartography (8)
	0,					-- Inscription (9)
	1044030,			-- Masonry (10)
	0,					-- Glassblowing (11)
}

CraftingWindow.firstMaterial2 = {
	0,					-- Alchemy (1)
	1060875,			-- Blacksmithing (2)
	0,					-- Cooking (3)
	0,					-- Carpentry (4)
	0,					-- Tailoring (5)
	0,					-- Bowcraft and Fletching (6)
	0,					-- Tinkering (7)
	0,					-- Cartography (8)
	0,					-- Inscription (9)
	0,					-- Masonry (10)
	0,					-- Glassblowing (11)
}

CraftingWindow.lastMaterial2 = {
	0,					-- Alchemy (1)
	1060880,			-- Blacksmithing (2)
	0,					-- Cooking (3)
	0,					-- Carpentry (4)
	0,					-- Tailoring (5)
	0,					-- Bowcraft and Fletching (6)
	0,					-- Tinkering (7)
	0,					-- Cartography (8)
	0,					-- Inscription (9)
	0,					-- Masonry (10)
	0,					-- Glassblowing (11)
}

CraftingWindow.MenuTitleTID = {
	1044001,			-- Alchemy (1)
	1044002,			-- Blacksmithing (2)
	1044003,			-- Cooking (3)
	1044004,			-- Carpentry (4)
	1044005,			-- Tailoring (5)
	1044006,			-- Bowcraft and Fletching (6)
	1044007,			-- Tinkering (7)
	1044008,			-- Cartography (8)
	1044009,			-- Inscription (9)
	1044500,			-- Masonry (10)
	1044622				-- Glassblowing (11)
	}

-- NOTE!!! IF THE .TXT FILES (IN Code\Server\rundir\scripts) THAT THESE CSV FILES ARE DERIVED FROM GET CHANGED (NEW RECIPES ADDED, ETC.)
-- THEN THE CSV FILES WILL NEED TO BE RE-CREATED!!!
CraftingWindow.CSVFilenames = {
	"alchemy.csv",
	"blacksmith.csv",
	"cooking.csv",
	"carpentry.csv",
	"tailor.csv",
	"fletcher.csv",
	"tinker.csv",
	"mapmaking.csv",
	"inscribe.csv",
	"masonry.csv",
	"glassblowing.csv",
	}
	
CraftingWindow.categoriesPerCraft = { 10, 10, 6, 10, 10, 3, 9, 1, 10, 4, 1 }

CraftingWindow.categoryButtonIds = { 9099, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010 }

CraftingWindow.RequestedTileArt = {}

----------------------------------------------------------------
-- CraftingWindow Functions
----------------------------------------------------------------

function CraftingWindow.Initialize()
	-- If another crafting window is already open, close it
	if CraftingWindow.windowName ~= nil then
		CraftingWindow.DestroyWindow(CraftingWindow.windowName)
	end

	TempCraftingWindow = {}
	if(UO_GenericGump.retrieveWindowData( TempCraftingWindow )) then	
		Interface.DestroyWindowOnClose[TempCraftingWindow.windowName] = true
	end
	if TempCraftingWindow.gumpID == CraftingWindow.InfoGump then
		CraftingWindow.InitializeInfoWindow()
	else
		CraftingWindow.InitializeMainWindow()
	end
end

function CraftingWindow.InitializeMainWindow()

	if(UO_GenericGump.retrieveWindowData( CraftingWindow )) then	
		Interface.DestroyWindowOnClose[CraftingWindow.windowName] = true
	end
	
	WindowUtils.RestoreWindowPosition(CraftingWindow.windowName, false, "CraftingWindow")

	for idx, val in pairs(CraftingWindow.MenuTitleTID) do
		if (val == tonumber(CraftingWindow.descData[1])) then
			if (idx ~= CraftingWindow.CraftingType) then
				CraftingWindow.CraftingType = idx
				CraftingWindow.ClearInfoWindow()
				CraftingWindow.selectedRecipe = 0
			end
			break
		end
	end

	CraftingWindow.RefreshInfoWindow()

	CraftingWindow.numRecipes = 0
	CraftingWindow.numCategories = 0
	CraftingWindow.itemList = {}
	CraftingWindow.numItems = 0
	CraftingWindow.MaterialSelection = false
	CraftingWindow.statusValues = {}
	CraftingWindow.buttonFlags = {}
	CraftingWindow.lastRecipeTID = 0
	CraftingWindow.ActionButtonsInRow = 0

	local titleString = LuaUtils.stripHTML(GetStringFromTid(tonumber(CraftingWindow.descData[1])))
	WindowUtils.SetActiveDialogTitle(titleString)

-- 	Commented out code to print gump data
--	Debug.Print("gumpId="..CraftingWindow.gumpID)
--	Debug.Print("descDataCount="..CraftingWindow.descDataCount)
--	for idx, val in pairs(CraftingWindow.descData) do
--		if (idx <= CraftingWindow.descDataCount) then
--			local name = GetStringFromTid(tonumber(val))
--			Debug.Print(L"descData["..idx..L"]="..name..L" ("..val..L")")
--		end
--	end

--	Debug.Print("buttonCount="..CraftingWindow.buttonCount)
--	for idx, val in pairs(CraftingWindow.buttonIDs) do
--		if (idx <= CraftingWindow.buttonCount) then
--			Debug.Print(L"buttonIDs["..idx..L"]="..val)
--		end
--	end

--	Debug.Print("stringCount="..CraftingWindow.stringDataCount)
--	for idx, val in pairs(CraftingWindow.stringData) do
--		if (idx <= CraftingWindow.StringDataCount) then
--			Debug.Print(L"stringData["..idx..L"]="..val)
--		end
--	end

	UOBuildTableFromCSV ("Data/GameData/"..CraftingWindow.CSVFilenames[CraftingWindow.CraftingType], "Recipes")
	CraftingWindow.parseItems()
	CraftingWindow.parseStatusTIDs()
	
		-- TODO: Real data
	WindowSetAlpha(CraftingWindow.windowName.."CategoryLabel", 0.5)
	WindowSetAlpha(CraftingWindow.windowName.."OptionsLabel", 0.5)
	WindowSetAlpha(CraftingWindow.windowName.."CreationLabel", 0.5)
	WindowSetAlpha(CraftingWindow.windowName.."ItemLabel", 0.5)
	WindowSetAlpha(CraftingWindow.windowName.."InfoLabel", 0.5)
	LabelSetText(CraftingWindow.windowName.."CategoryLabelText", GetStringFromTid(1079445)) --"Category"
	LabelSetText(CraftingWindow.windowName.."OptionsLabelText", GetStringFromTid(1079446)) --"Options"
	LabelSetText(CraftingWindow.windowName.."CreationLabelText", GetStringFromTid(1079447)) --"Creation"
	LabelSetText(CraftingWindow.windowName.."ItemLabelText", GetStringFromTid(1079448)) --"Items"
	LabelSetText(CraftingWindow.windowName.."InfoLabelText", GetStringFromTid(1079449)) --"Info"
	

	local name = GetStringFromTid(1044014)	-- "LAST TEN"
	CraftingWindow.AddCategory(name)

	local firstCategory = 0
	for idx, val in pairs(CraftingWindow.descData) do
		if (tonumber(val) == 1044011) then
			firstCategory = idx
			break
		end
	end

	for i = 1, CraftingWindow.categoriesPerCraft[CraftingWindow.CraftingType] do
		name = GetStringFromTid(tonumber(CraftingWindow.descData[i+firstCategory]))
		CraftingWindow.AddCategory(name)
		if (CraftingWindow.lastRecipeTID == 0 and i == CraftingWindow.categoriesPerCraft[CraftingWindow.CraftingType]) then
			-- if there were no recipes, save the last category for notice parsing
			CraftingWindow.lastRecipeTID = CraftingWindow.descData[i+firstCategory]
		end
	end

	if (CraftingWindow.CraftingType == 1 or CraftingWindow.CraftingType == 8 or CraftingWindow.CraftingType == 11) then
		-- For alchemy, cartography, and glassblowing, use the LAST TID
		labelTID = tonumber(CraftingWindow.descData[CraftingWindow.descDataCount])
	else
		-- Otherwise, use the next-to-last TID
		labelTID = tonumber(CraftingWindow.descData[CraftingWindow.descDataCount-1])
	end
	-- If the next-to-last TID is a material color button label, or the final recipe, then leave "notices" field blank
	-- Otherwise, print the message.
	if (labelTID == 1061590 or labelTID == 1061591 or labelTID == CraftingWindow.lastRecipeTID or labelTID == 1044525 or
		(labelTID >= CraftingWindow.firstMaterial1[CraftingWindow.CraftingType] and labelTID <= CraftingWindow.lastMaterial1[CraftingWindow.CraftingType])) then
		LabelSetText(CraftingWindow.windowName.."NoticesText", GetStringFromTid(1079173)) -- "CRAFTING ACTIONS"
	else
		LabelSetText(CraftingWindow.windowName.."NoticesText", GetStringFromTid(tonumber(labelTID)))
	end
	
	-- Options Window
	LabelSetText( CraftingWindow.windowName.."OptionsWindowMaterialComboLabel", GetStringFromTid(1079450)) --"Select Material"
	LabelSetText( CraftingWindow.windowName.."OptionsWindowQuestMarkLabel", GetStringFromTid(1079451)) --"Toggle as Quest Item" 

	for matType = 1,2 do
		CraftingWindow.SetupMaterialSelection(matType)
	end


	if (CraftingWindow.buttonFlags[CraftingWindow.RecycleButtonID]) then
		CraftingWindow.buttonText[CraftingWindow.RecycleButtonID] = GetStringFromTid(1044016)	-- 7000 "Smelt Item"
	else
		WindowSetShowing(CraftingWindow.windowName.."OptionsWindowActionButton1", false)
		CraftingWindow.buttonText[CraftingWindow.RecycleButtonID] = L""
	end
	ButtonSetText(SystemData.ActiveWindow.name.."OptionsWindowActionButton1", CraftingWindow.buttonText[CraftingWindow.RecycleButtonID])		-- 7000 "Smelt Item"
	

	if (CraftingWindow.buttonFlags[CraftingWindow.RepairButtonID]) then
		CraftingWindow.buttonText[CraftingWindow.RepairButtonID] = GetStringFromTid(1044015)	-- 8000 "Repair Item"
	else
		WindowSetShowing(CraftingWindow.windowName.."OptionsWindowActionButton4", false)
		CraftingWindow.buttonText[CraftingWindow.RepairButtonID] = L""
	end
	ButtonSetText(CraftingWindow.windowName.."OptionsWindowActionButton4", CraftingWindow.buttonText[CraftingWindow.RepairButtonID])			-- 8000 "Repair Item"

	if (CraftingWindow.buttonFlags[CraftingWindow.MarkButtonID]) then
		-- TODO: Localize
		LabelSetText( CraftingWindow.windowName.."OptionsWindowMarkItemLabel", GetStringFromTid(1079452)) --"Mark Item"
		if (CraftingWindow.buttonFlags[CraftingWindow.MarkItemButtonToggle]) then
			ButtonSetStayDownFlag( CraftingWindow.windowName.."OptionsWindowMarkItemButton", true )
			ButtonSetPressedFlag( CraftingWindow.windowName.."OptionsWindowMarkItemButton", true )
		end

	else
		WindowSetShowing(CraftingWindow.windowName.."OptionsWindowMarkItem", false)
	end	

	if (CraftingWindow.buttonFlags[CraftingWindow.QuestMarkButtonToggle]) then
		ButtonSetStayDownFlag( CraftingWindow.windowName.."OptionsWindowQuestMarkButton", true )
		ButtonSetPressedFlag( CraftingWindow.windowName.."OptionsWindowQuestMarkButton", true )
	end		

	if (CraftingWindow.buttonFlags[CraftingWindow.EnhanceButtonID]) then
		CraftingWindow.buttonText[CraftingWindow.EnhanceButtonID] = GetStringFromTid(1061001)	-- 2000 "Enhance Item"
	else
		WindowSetShowing(CraftingWindow.windowName.."OptionsWindowActionButton6", false)
		CraftingWindow.buttonText[CraftingWindow.EnhanceButtonID] = L""
	end
	ButtonSetText(CraftingWindow.windowName.."OptionsWindowActionButton6", CraftingWindow.buttonText[CraftingWindow.EnhanceButtonID])	-- 2000 "Enhance Item"

	if (CraftingWindow.buttonFlags[CraftingWindow.AlterItemButtonID]) then
		CraftingWindow.buttonText[CraftingWindow.AlterItemButtonID] = GetStringFromTid(1094726)	-- 9000 "Alter Item"
	else
		WindowSetShowing(CraftingWindow.windowName.."OptionsWindowActionButtonAlterItem", false)
		CraftingWindow.buttonText[CraftingWindow.AlterItemButtonID] = L""
	end
	ButtonSetText(CraftingWindow.windowName.."OptionsWindowActionButtonAlterItem", CraftingWindow.buttonText[CraftingWindow.AlterItemButtonID])	-- 9000 "Alter Item"

	LabelSetText( CraftingWindow.windowName.."CreationWindowMakeLabel", GetStringFromTid(1079453)) --"Make:" 
	if (CraftingWindow.lastRecipeTID ~= 0) then
		makeLastLabel = GetStringFromTid(1044013) --..L": " + GetStringFromTid(CraftingWindow.lastRecipeTID)
		LabelSetText( CraftingWindow.windowName.."CreationWindowMakeLastLabel", makeLastLabel )
	else
		WindowSetShowing(CraftingWindow.windowName.."CreationWindowMakeLastLabel", false)
	end	
	LabelSetText( CraftingWindow.windowName.."CreationWindowMakeNumLabel", GetStringFromTid(1079454)) --"Make Number" 
	LabelSetText( CraftingWindow.windowName.."CreationWindowMakeMaxLabel", GetStringFromTid(1079455)) --"Make Max" 
	if (CraftingWindow.localizedDataCount > 0) then	
		LabelSetText( CraftingWindow.windowName.."CreationWindowCompleteCount", CraftingWindow.localizedData[CraftingWindow.localizedDataCount] )
	end
	TextEditBoxSetText( CraftingWindow.windowName.."CreationWindowMakeNumTextBox", L""..0)
	if (CraftingWindow.buttonFlags[CraftingWindow.MakeLastButtonToggle]) then
		ButtonSetStayDownFlag( CraftingWindow.windowName.."CreationWindowMakeLastButton", true )
		ButtonSetPressedFlag( CraftingWindow.windowName.."CreationWindowMakeLastButton", true )
	end
	if (CraftingWindow.buttonFlags[CraftingWindow.MakeMaxButtonToggle]) then
		ButtonSetStayDownFlag( CraftingWindow.windowName.."CreationWindowMakeMaxButton", true )
		ButtonSetPressedFlag( CraftingWindow.windowName.."CreationWindowMakeMaxButton", true )
	else
		for id = CraftingWindow.MakeNumButtonToggle, CraftingWindow.MakeNumButtonToggle+CraftingWindow.MaxMakeNum do
			if (CraftingWindow.buttonFlags[id]) then
				ButtonSetStayDownFlag( CraftingWindow.windowName.."CreationWindowMakeNumButton", true )
				ButtonSetPressedFlag( CraftingWindow.windowName.."CreationWindowMakeNumButton", true )
				num = id-CraftingWindow.MakeNumButtonToggle
				TextEditBoxSetText( CraftingWindow.windowName.."CreationWindowMakeNumTextBox", L""..num )
				break
			end
		end
	end
	-- The cancel button doesn't work because user input is disabled while making objects 
	--if (CraftingWindow.buttonFlags[CraftingWindow.MakeCancelButtonID]) then
		-- Disable everything other than cancel button, make now becomes cancel button
		--ButtonSetText(CraftingWindow.windowName.."CreationWindowMakeItem", GetStringFromTid(1011012))
	--else
		ButtonSetText(CraftingWindow.windowName.."CreationWindowMakeItem", GetStringFromTid(1044151))	-- special (based on recipe) (10002) "MAKE NOW"
		if (CraftingWindow.selectedRecipe == 0 and not ButtonGetPressedFlag(CraftingWindow.windowName.."CreationWindowMakeLastButton")) then
			ButtonSetDisabledFlag(CraftingWindow.windowName.."CreationWindowMakeItem", true)
		end
	--end

	CraftingWindow.Show()
end

function CraftingWindow.SetIcon(window, obj, hue)
	-- Object 0 means no picture(?)
	if obj == 0 then
		return
	end

	local name, x, y, scale, newWidth, newHeight = RequestTileArt(obj, 50, 50)
	CraftingWindow.RequestedTileArt[#CraftingWindow.RequestedTileArt + 1] = name
	DynamicImageSetTextureDimensions(window, newWidth, newHeight)
	WindowSetDimensions(window, newWidth, newHeight)		
	DynamicImageSetTexture(window, name, 0, 0 )
	if hue ~= 0 then
		local r, g, b, a = HueRGBAValue(hue)
		WindowSetTintColor( window, r, g, b )
	end
	
	DynamicImageSetTextureScale(window, scale)
	local parent = WindowGetParent(window)
	WindowClearAnchors(window)
	WindowAddAnchor(window, "topleft", parent, "topleft", ((50-newWidth)/2), ((50-newHeight)/2))
end

-- Text: wstring with recipe name
-- matNum: The material index from the Lua materials list (off by 1 from the server)
-- recipeNum: The index of the recipe from the big list for the skill
-- iconNum: tile number of the item
-- TODO: Hue
function CraftingWindow.AddRecipe(text, recipeNum, iconNum)
	CraftingWindow.numRecipes = CraftingWindow.numRecipes + 1
	local curr = CraftingWindow.numRecipes

	local recipe = CraftingWindow.windowName.."Recipe"..curr
	if not DoesWindowNameExist(recipe) then
		CreateWindowFromTemplate(recipe, "RecipeTemplate", CraftingWindow.windowName.."ListViewScrollChild")
	end
	
	if curr == 1 then
		WindowAddAnchor(recipe, "topleft", CraftingWindow.windowName.."ListViewScrollChild", "topleft", 0, 0)
	else
		WindowAddAnchor(recipe, "bottomleft", CraftingWindow.windowName.."Recipe"..curr-1, "topleft", 0, 1)
	end
	WindowSetId(recipe, recipeNum)
	ButtonSetText(recipe.."Button", text)
	if (recipeNum == selectedRecipe) then
		ButtonSetHighlightFlag(recipe.."Button", true)
	end
end

function CraftingWindow.SetupMaterialSelection(matType)
	if (not CraftingWindow.statusValues["mat"..matType]) then
		WindowSetShowing(CraftingWindow.windowName.."OptionsWindowMaterial"..matType, false)
		return
	end

	if (CraftingWindow.CraftingType ~= 10) then
		LabelSetText( CraftingWindow.windowName.."OptionsWindowMaterial"..matType.."UseColorLabel", GetStringFromTid(1079456)) --"Use Color" 
		if (CraftingWindow.statusValues["mat"..matType.."color"] == 1061590) then
			ButtonSetStayDownFlag( CraftingWindow.windowName.."OptionsWindowMaterial"..matType.."UseColorButton", false )
			ButtonSetPressedFlag( CraftingWindow.windowName.."OptionsWindowMaterial"..matType.."UseColorButton", false )
		else
			ButtonSetStayDownFlag( CraftingWindow.windowName.."OptionsWindowMaterial"..matType.."UseColorButton", true )
			ButtonSetPressedFlag( CraftingWindow.windowName.."OptionsWindowMaterial"..matType.."UseColorButton", true )
		end
	end
	if (matType == 1) then
		bottomTID = CraftingWindow.firstMaterial1[CraftingWindow.CraftingType]
		topTID = CraftingWindow.lastMaterial1[CraftingWindow.CraftingType]
	elseif (matType == 2) then
		bottomTID = CraftingWindow.firstMaterial2[CraftingWindow.CraftingType]
		topTID = CraftingWindow.lastMaterial2[CraftingWindow.CraftingType]
	end
	stringOffset = 0
	if (matType == 2) then
		offsetBottomTID = CraftingWindow.firstMaterial1[CraftingWindow.CraftingType]
		offsetTopTID = CraftingWindow.lastMaterial1[CraftingWindow.CraftingType]
		-- Skip all of material type 1 strings plus the material button for legacy
		stringOffset = (offsetTopTID - offsetBottomTID)+1
	end
	
	for curr = 1, (topTID-bottomTID)+1 do
		local materialTID = curr - 1 + bottomTID
		
		selectionIndex = stringOffset+curr
		-- the last localizedData item is the complete count info, so check against ocalizedDataCount-1
		if (selectionIndex <= (CraftingWindow.localizedDataCount-1)) then	
			selectionText = CraftingWindow.localizedData[selectionIndex]
		else
			if (CraftingWindow.CraftingType == 10 and curr == 1) then
				-- Masonry calls its first material "NORMAL", instead of "IRON"
				selectionText = GetStringFromTid(1044525)
			else
				selectionText = GetStringFromTid(materialTID)
			end
		end
		
		ComboBoxAddMenuItem( CraftingWindow.windowName.."OptionsWindowMaterial"..matType.."MaterialCombo", selectionText )

	end
	local sel = 1
	if (CraftingWindow.statusValues["mat"..matType] == 1044525) then
		sel = 1
	else
		sel = (CraftingWindow.statusValues["mat"..matType] - bottomTID)+1
	end
	ComboBoxSetSelectedMenuItem(CraftingWindow.windowName.."OptionsWindowMaterial"..matType.."MaterialCombo", sel)
end

-- Text: wstring with category name
-- categoryNum: The index of the category from the big list for the skill
function CraftingWindow.AddCategory(text)
	CraftingWindow.numCategories = CraftingWindow.numCategories + 1
	local curr = CraftingWindow.numCategories

	local category = CraftingWindow.windowName.."Category"..curr
	if not DoesWindowNameExist(category) then
		CreateWindowFromTemplate(category, "CategoryTemplate", CraftingWindow.windowName.."CatListViewCatScrollChild")
	end
	
	if curr == 1 then
		WindowAddAnchor(category, "topleft", CraftingWindow.windowName.."CatListViewCatScrollChild", "topleft", 0, 0)
	else
		WindowAddAnchor(category, "bottomleft", CraftingWindow.windowName.."Category"..curr-1, "topleft", 0, 1)
	end

	WindowSetId(category, CraftingWindow.categoryButtonIds[curr])

	ButtonSetText(category.."Button", text)
end

function CraftingWindow.Show()
-- non-legacy:
--	for idx, rec in pairs(WindowData.Recipes) do
--		for matidx, material in { L"iron" } do -- TODO: s/b CraftingWindow.Materials[skillNum]
--			local name = material..L" "..GetStringFromTid(rec["GumpTID"])
--			CraftingWindow.AddRecipe(name, matidx, rec["RecipeID"], rec["ResultObjType"])
--		end
--	end

	ScrollWindowSetOffset(CraftingWindow.windowName.."ListView", 0 )
	ScrollWindowUpdateScrollRect(CraftingWindow.windowName.."ListView")
	--WindowRefreshScrollChild("CraftingWindowListViewScrollChild")

end

function FindRecipeRecord(recipeId)
	for recipeIdx, recipeRec in pairs(WindowData.Recipes) do
		if (recipeId == recipeRec["RecipeID"]) then
			return recipeRec
		end
	end
	recipeRec = {}
	return recipeRec
end

function CraftingWindow.parseItems()
	for buttonIdx, buttonVal in pairs(CraftingWindow.buttonIDs) do
		--Debug.Print("index = "..buttonIdx.." val = "..buttonVal.." count = "..CraftingWindow.buttonCount)
		if (buttonIdx <= CraftingWindow.buttonCount) then
			CraftingWindow.buttonFlags[buttonVal] = true
			if (buttonVal == 1999 or buttonVal == 2000 or buttonVal == 6000 or buttonVal == 7000 or buttonVal == 8000) then
				CraftingWindow.ActionButtonsInRow = CraftingWindow.ActionButtonsInRow + 1
			end
			if (buttonVal > 0 and buttonVal < 1000) then	-- This button is a recipe
				local recipeRec = {}
				recipeRec = FindRecipeRecord(buttonVal)
				if (buttonVal == recipeRec["RecipeID"]) then
					local name = GetStringFromTid(recipeRec["GumpTID"])
					CraftingWindow.AddRecipe(name, recipeRec["RecipeID"], recipeRec["GumpPic"])
					-- And a sad little hack, to help parse the TIDs sent by the server:
					CraftingWindow.lastRecipeTID = recipeRec["GumpTID"]
				end
			end
		end
	end

	if (CraftingWindow.firstMaterial1[CraftingWindow.CraftingType] ~= 0) then
		CraftingWindow.ActionButtonsInRow = CraftingWindow.ActionButtonsInRow + 1
	end
	if (CraftingWindow.firstMaterial2[CraftingWindow.CraftingType] ~= 0) then
		CraftingWindow.ActionButtonsInRow = CraftingWindow.ActionButtonsInRow + 1
	end
end

function CraftingWindow.parseStatusTIDs()
-- Ugly, but no other way:
-- Starting with the last TID passed from the server, trace back, looking for status values:
	local TIDIndex = CraftingWindow.descDataCount
	local didMat2Color = false
	-- If there is no second material for this craft, mark the second material as done:
	if (CraftingWindow.firstMaterial2[CraftingWindow.CraftingType] == 0) then
		didMat2Color = true
	end
		-- Alchemy, cartography, and glassblowing have no materials and takes no mark, so skip this block:
	if (CraftingWindow.CraftingType ~= 1 and CraftingWindow.CraftingType ~= 8 and CraftingWindow.CraftingType ~= 11) then
		while TIDIndex > 0 do
			local thisTID = tonumber(CraftingWindow.descData[TIDIndex])
			-- looking for "MARK ITEM", "DO NOT MARK", "PROMPT FOR MARK"
			if (thisTID >= 1044017 and thisTID <= 1044019) then
				CraftingWindow.statusValues["mark"] = thisTID
				-- if no materials, then we have the only thing we need, so exit:
				if (CraftingWindow.firstMaterial1[CraftingWindow.CraftingType] == 0) then
					break;
				end
			-- looking for "USE MATERIAL COLOR" or "DO NOT COLOR" for 2nd material
			elseif ((not didMat2Color) and thisTID >= 1061590 and thisTID <= 1061591) then
				CraftingWindow.statusValues["mat2color"] = thisTID
				didMat2Color = true
			-- looking for 2nd material
			elseif (thisTID >= CraftingWindow.firstMaterial2[CraftingWindow.CraftingType] and
				thisTID <= CraftingWindow.lastMaterial2[CraftingWindow.CraftingType]) then
				CraftingWindow.statusValues["mat2"] = thisTID
			-- looking for "USE MATERIAL COLOR" or "DO NOT COLOR" for 1st material
			elseif (thisTID >= 1061590 and thisTID <= 1061591) then
				CraftingWindow.statusValues["mat1color"] = thisTID
			-- looking for 1st material
			elseif ((thisTID >= CraftingWindow.firstMaterial1[CraftingWindow.CraftingType] and
				thisTID <= CraftingWindow.lastMaterial1[CraftingWindow.CraftingType]) or
				-- funky special case: masonry calls its first material "NORMAL" instead of "IRON"
				(CraftingWindow.CraftingType == 10 and thisTID == 1044525)) then
				CraftingWindow.statusValues["mat1"] = thisTID
				break
			end

			TIDIndex = TIDIndex - 1
		end
	end
	labelTID = tonumber(CraftingWindow.descData[CraftingWindow.descDataCount-1])
end

function CraftingWindow.OnItemClicked()
	if( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_NONE ) then
		recipeNum = WindowGetId(SystemData.ActiveWindow.name)
		if (recipeNum < 1000) then
			--CraftingWindow.selectedRecipe = recipeNum
			recipeRec = FindRecipeRecord(recipeNum)
			if (recipeNum == recipeRec["RecipeID"]) then
				CraftingWindow.selectedRecipe = recipeNum
				ButtonSetHighlightFlag(SystemData.ActiveWindow.name.."Button", true)
				ButtonSetDisabledFlag(CraftingWindow.windowName.."CreationWindowMakeItem", false)
				local name = GetStringFromTid(recipeRec["GumpTID"])
				--LabelSetText(CraftingWindow.windowName.."SelectedItemText", name)
				buttonNum = CraftingWindow.selectedRecipe + 1000
				CraftingWindow.OnDefaultClicked(buttonNum)
			end
		else
			-- Must be a material (metal or scales)
			CraftingWindow.OnDefaultClicked(recipeNum)
		end
	end
end

function CraftingWindow.OnItemDblClicked()
	containerId = WindowGetId(WindowUtils.GetActiveDialog())
	slotNum = WindowGetId(SystemData.ActiveWindow.name)
	objectId = WindowData.ContainerWindow[containerId].ContainedItems[slotNum].objectId
	
	--UserActionUseItem(objectId,false)
end

function CraftingWindow.OnCategoryClicked()
	local buttonNum = WindowGetId(SystemData.ActiveWindow.name)
	ButtonSetHighlightFlag(SystemData.ActiveWindow.name.."Button", true)
	CraftingWindow.OnDefaultClicked(buttonNum)
	CraftingWindow.ClearInfoWindow()
end

function CraftingWindow.OnActionClicked()

	if (CraftingWindow.windowName == nil) then
		return
	end
	
	local buttonNum = WindowGetId(SystemData.ActiveWindow.name)
	if (buttonNum == 10002) then
		if (CraftingWindow.buttonFlags[CraftingWindow.MakeCancelButtonID]) then
			buttonNum = CraftingWindow.MakeCancelButtonID
		elseif(ButtonGetPressedFlag(CraftingWindow.windowName.."CreationWindowMakeLastButton")) then
			buttonNum = CraftingWindow.MakeLastButtonID
		elseif (CraftingWindow.selectedRecipe ~= 0) then
			buttonNum = CraftingWindow.selectedRecipe
		else
			return
		end
	elseif (buttonNum == 10003) then
		buttonNum = CraftingWindow.selectedRecipe + 1000
		-- The "Info" button will return the value of the recipe the user selected earlier
		if (CraftingWindow.selectedRecipe == 0) then
		-- if no recipe has been selected, do nothing
			return
		end
	else
		-- if this button wasn't enabled (wasn't sent to us by server), then do nothing
		if (not CraftingWindow.buttonFlags[buttonNum]) then
			return
		end
	end

	CraftingWindow.OnDefaultClicked(buttonNum)
end

function CraftingWindow.SendServerButtonInfo(buttonNumber, window)
	UO_GenericGump.broadcastButtonPress( buttonNumber, window )
end

function CraftingWindow.OnDefaultClicked(buttonNum)
	CraftingWindow.SendServerButtonInfo(buttonNum, CraftingWindow)
	CraftingWindow.DestroyWindow(CraftingWindow.windowName)
end

function CraftingWindow.Shutdown()
	if CraftingWindow.RequestedTileArt then
		for _, art in pairs( CraftingWindow.RequestedTileArt ) do
			ReleaseTileArt( art )
		end
	end
	
	if CraftingWindow.windowName and DoesWindowNameExist(SystemData.ActiveWindow.name) then
		WindowUtils.SaveWindowPosition(SystemData.ActiveWindow.name, false, "CraftingWindow")
	end
end

function CraftingWindow.DestroyWindow(myWindowName)
	if (myWindowName ~= nil) and DoesWindowNameExist(myWindowName) then
		WindowUtils.SaveWindowPosition(myWindowName, false, "CraftingWindow")
		DestroyWindow(myWindowName)
	end
	UOUnloadCSVTable("Recipes")
	CraftingWindow.windowName = nil
end

-- OnMouseOver Handler (tooltips)
function CraftingWindow.ItemMouseOver()
	btnName = SystemData.ActiveWindow.name

--	text = GetStringFromTid(data.ToolTipTid)
	local text = CraftingWindow.buttonText[WindowGetId(btnName)]

	Tooltips.CreateTextOnlyTooltip(btnName, text)
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end


-- Not legacy:

function Split(wstr, delim)
	return unpack(SplitTable(wstr, delim))
end

function SplitTable(wstr, delim)
	delim = delim or L"%s"
	result = {}
	init = 1
	start, fin = wstring.find(wstr, delim)
	while start do
		sub = wstring.sub(wstr, init, start-1)
		table.insert(result, sub)
		init = fin + 1
		start, fin = wstring.find(wstr, delim, init)
	end

	table.insert(result, wstring.sub(wstr, init))

	return result
end

function AddToIndex(wstr, value)
	local bucket = CraftingWindow.index
	for i = 1, 4 do 
		if i > wstring.len(wstr) then
			break
		else
			local key = wstring.sub(wstr, i, i)
			bucket[key] = bucket[key] or {}
			bucket = bucket[key]
		end
	end

	bucket[1] = bucket[1] or {}
	table.insert(bucket[1], value)
end

function CraftingWindow.ApplyFilter()
	local filter = wstring.lower(TextEditBoxGetText("CraftingWindowFilterInput"))
	local fin = math.min(wstring.len(filter), 4)

	-- If the filter is cleared, show all recipes
	if fin == 0 then
		ShowAllRecipes()
		return
	end

	local bucket = CraftingWindow.index
	for i = 1, fin do
		key = wstring.sub(filter, i, i)
		if not bucket[key] then
			break
		end
		bucket = bucket[key]
	end

	CraftingWindow.previousRecipe = nil
	HideAllRecipes(false)
	ShowFilteredRecipes(bucket)
end

function ShowFilteredRecipes(bucket)
	for k, v in pairs(bucket) do
		if type(v) ~= 'table' then
			Debug.Print('Got a bad filter entry')
		end

		if v.slot then
			local recipe = "CraftingWindowRecipe"..v.slot
			WindowClearAnchors(recipe)
			if not CraftingWindow.previousRecipe then
				WindowAddAnchor(recipe, "topleft", CraftingWindow.windowName.."ListViewScrollChild", "topleft", 0, 0)
			else
				WindowAddAnchor(recipe, "bottomleft", CraftingWindow.previousRecipe, "topleft", 0, 1)
			end
			WindowSetShowing(recipe, true)
			CraftingWindow.previousRecipe = recipe
		else
			ShowFilteredRecipes(v)
		end
	end
end

function ShowAllRecipes()
	for i = 1, CraftingWindow.numRecipes do
		local recipe = "CraftingWindowRecipe"..i
		WindowSetShowing(recipe, true)
		WindowClearAnchors(recipe)
		if i == 1 then
			WindowAddAnchor(recipe, "topleft", CraftingWindow.windowName.."ListViewScrollChild", "topleft", 0, 0)
		else
			WindowAddAnchor(recipe, "bottomleft", "CraftingWindowRecipe"..i-1, "topleft", 0, 1)
		end
	end
end

function HideAllRecipes()
	for i = 1, CraftingWindow.numRecipes do
		local slot = "CraftingWindowRecipe"..i
		WindowSetShowing(slot, false)
	end
end

function CraftingWindow.ToggleCheckBox()
	isPressed = ButtonGetPressedFlag(SystemData.ActiveWindow.name.."Button")
	ButtonSetStayDownFlag( SystemData.ActiveWindow.name.."Button", not isPressed )
	ButtonSetPressedFlag( SystemData.ActiveWindow.name.."Button", not isPressed )
	if (SystemData.ActiveWindow.name == CraftingWindow.windowName.."OptionsWindowMaterial1UseColor") then
		CraftingWindow.OnDefaultClicked(CraftingWindow.MaterialUseColor1Toggle)
	elseif (SystemData.ActiveWindow.name == CraftingWindow.windowName.."OptionsWindowMaterial2UseColor") then
		CraftingWindow.OnDefaultClicked(CraftingWindow.MaterialUseColor2Toggle)
	elseif (SystemData.ActiveWindow.name == CraftingWindow.windowName.."OptionsWindowMarkItem") then
		CraftingWindow.OnDefaultClicked(CraftingWindow.MarkItemButtonToggle)
	elseif (SystemData.ActiveWindow.name == CraftingWindow.windowName.."OptionsWindowQuestMark") then
		CraftingWindow.OnDefaultClicked(CraftingWindow.QuestMarkButtonToggle)
	elseif (SystemData.ActiveWindow.name == CraftingWindow.windowName.."CreationWindowMakeLast") then
		WindowSetShowing(CraftingWindow.windowName.."CreationWindowMakeItem", not isPressed)
		CraftingWindow.OnDefaultClicked(CraftingWindow.MakeLastButtonToggle)
	elseif (SystemData.ActiveWindow.name == CraftingWindow.windowName.."CreationWindowMakeNum") then
		if (not isPressed) then
			makeNum = TextEditBoxGetText( CraftingWindow.windowName.."CreationWindowMakeNumTextBox" )
			intMakeNum = 0 + makeNum
			if(intMakeNum <= 0) then
				intMakeNum = 1
				TextEditBoxSetText( CraftingWindow.windowName.."CreationWindowMakeNumTextBox", L""..intMakeNum )
			elseif(intMakeNum > CraftingWindow.MaxMakeNum) then
				intMakeNum = CraftingWindow.MaxMakeNum
				TextEditBoxSetText( CraftingWindow.windowName.."CreationWindowMakeNumTextBox", L""..intMakeNum )
			else
				CraftingWindow.OnDefaultClicked(CraftingWindow.MakeNumButtonToggle+intMakeNum)
			end
		else
			CraftingWindow.OnDefaultClicked(CraftingWindow.MakeOneButtonToggle)
		end
	elseif (SystemData.ActiveWindow.name == CraftingWindow.windowName.."CreationWindowMakeMax") then
		if (not isPressed) then
			CraftingWindow.OnDefaultClicked(CraftingWindow.MakeMaxButtonToggle)
		else
			CraftingWindow.OnDefaultClicked(CraftingWindow.MakeOneButtonToggle)
		end
	end
end

function CraftingWindow.SelectMaterial()

	-- which material
	local materialNum = 0
	if (SystemData.ActiveWindow.name == CraftingWindow.windowName.."OptionsWindowMaterial1MaterialCombo") then
		materialNum = CraftingWindow.MaterialBase1
	elseif (SystemData.ActiveWindow.name == CraftingWindow.windowName.."OptionsWindowMaterial2MaterialCombo") then
		materialNum = CraftingWindow.MaterialBase2
	else
		return
	end
	local selection = ComboBoxGetSelectedMenuItem(SystemData.ActiveWindow.name)

	materialNum = materialNum + (selection-1)

	CraftingWindow.OnDefaultClicked(materialNum)
end

function CraftingWindow.InitializeInfoWindow()
								 
	if(UO_GenericGump.retrieveWindowData( CraftingWindow2 )) then	
		Interface.DestroyWindowOnClose[CraftingWindow2.windowName] = true
	end
	WindowSetShowing(CraftingWindow2.windowName, false)
	CraftingWindow2.parsedText = {}
	CraftingWindow2.recipeRec = {}
	CraftingWindow2.recipeID = CraftingWindow.selectedRecipe
	UOBuildTableFromCSV ("Data/GameData/"..CraftingWindow.CSVFilenames[CraftingWindow.CraftingType], "Recipes")
	CraftingWindow2.findRecipeRecord()
	CraftingWindow2.parseTIDs()
	
	CraftingWindow.SendServerButtonInfo(CraftingWindow.InfoBackButtonID, CraftingWindow2)
	CraftingWindow.DestroyWindow(CraftingWindow2.windowName)
end

function CraftingWindow.ClearInfoWindow()
	CraftingWindow2.parsedText = nil
	CraftingWindow2.recipeRec = nil
	CraftingWindow2.recipeID = 0
	CraftingWindow2.windowName = nil
end

function CraftingWindow.RefreshInfoWindow()

	if (CraftingWindow2.parsedText == nil) or (CraftingWindow.selectedRecipe == 0) then
		return
	end

	if (CraftingWindow2.recipeRec ~= nil) and (CraftingWindow2.recipeRec["GumpPic"] ~= 0) then
		local name, x, y, scale, newWidth, newHeight = RequestTileArt(CraftingWindow2.recipeRec["GumpPic"], 55, 55)
		CraftingWindow2.RequestedTileArt[#CraftingWindow2.RequestedTileArt + 1] = name
		DynamicImageSetTextureDimensions(CraftingWindow.windowName.."InfoWindowIcon", newWidth, newHeight)
		WindowSetDimensions(CraftingWindow.windowName.."InfoWindowIcon", newWidth, newHeight)
		DynamicImageSetTexture(CraftingWindow.windowName.."InfoWindowIcon", name, 0, 0 )
		DynamicImageSetTextureScale(CraftingWindow.windowName.."InfoWindowIcon", scale)
	end
	
	CraftingWindow.SetInfoLabel(1)
	CraftingWindow.SetInfoLabel(2)
	CraftingWindow.SetInfoLabel(2.5)
	CraftingWindow.SetInfoLabel(3)
	CraftingWindow.SetInfoLabel(3.5)
	CraftingWindow.SetInfoLabel(4)
	CraftingWindow.SetInfoLabel(4.5)
	CraftingWindow.SetInfoLabel(5)
	CraftingWindow.SetInfoLabel(5.5)
	CraftingWindow.SetInfoLabel(6)
	CraftingWindow.SetInfoLabel(6.5)
	CraftingWindow.SetInfoLabel(7)
	CraftingWindow.SetInfoLabel(7.5)
	CraftingWindow.SetInfoLabel(8)
	CraftingWindow.SetInfoLabel(8.5)
	CraftingWindow.SetInfoLabel(9)
	CraftingWindow.SetInfoLabel(9.5)
	CraftingWindow.SetInfoLabel(10)
	CraftingWindow.SetInfoLabel(10.5)
	CraftingWindow.SetInfoLabel(11)
	CraftingWindow.SetInfoLabel(12)
	CraftingWindow.SetInfoLabel(13)
	CraftingWindow.SetInfoLabel(14)
	CraftingWindow.SetInfoLabel(15)
	
end
	
function CraftingWindow.SetInfoLabel(num)
	if ((CraftingWindow2.parsedText ~= nil) and (CraftingWindow2.parsedText[num] ~= nil)) then
		LabelSetText(CraftingWindow.windowName.."InfoWindowLabel"..num, CraftingWindow2.parsedText[num])
	else
		LabelSetText(CraftingWindow.windowName.."InfoWindowLabel"..num, L"")
	end
end

function CraftingWindow.OnMakeNumTextChanged()
	makeNum = TextEditBoxGetText( CraftingWindow.windowName.."CreationWindowMakeNumTextBox" )
	intMakeNum = 0 + makeNum
	isPressed = ButtonGetPressedFlag(CraftingWindow.windowName.."CreationWindowMakeNumButton")
	if (isPressed and (intMakeNum > 0) and (intMakeNum < 100)) then
		CraftingWindow.OnDefaultClicked(CraftingWindow.MakeNumButtonToggle+intMakeNum)
	end
end
