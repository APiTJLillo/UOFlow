
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

CraftingWindow2 = {}

CraftingWindow2.parsedText = {}
CraftingWindow2.recipeRec = {}
CraftingWindow2.recipeID = 0
CraftingWindow2.colorable = false

CraftingWindow2.skillTIDs =
{
	[0]=1044060,	-- Alchemy
	[7]=1044067,	-- Blacksmithy
	[8]=1044068,	-- Bowcraft and Fletching
	[11]=1044071,	-- Carpentry
	[12]=1044072,	-- Cartography
	[13]=1044073,	-- Cooking
	[23]=1044083,	-- Inscription
	[25]=1044085,	-- Magery
	[29]=1044089,	-- Musicianship
	[34]=1044094,	-- Tailoring
	[37]=1044097,	-- Tinkering
}

CraftingWindow2.RequestedTileArt = {}

----------------------------------------------------------------
-- CraftingWindow Functions
----------------------------------------------------------------

function CraftingWindow2.Initialize()

	if(UO_GenericGump.retrieveWindowData( CraftingWindow2 )) then	
		Interface.DestroyWindowOnClose[CraftingWindow2.windowName] = true
	end

	CraftingWindow2.parsedText = {}
	CraftingWindow2.recipeRec = {}
	CraftingWindow2.recipeID = CraftingWindow.selectedRecipe

	WindowUtils.RestoreWindowPosition(CraftingWindow2.windowName, false, "CraftingWindow")

	local titleString = LuaUtils.stripHTML(GetStringFromTid(tonumber(CraftingWindow2.descData[4])))
	WindowUtils.SetActiveDialogTitle(titleString)
--	Debug.Print("gumpId="..CraftingWindow2.gumpID)

--	Debug.Print("descDataCount="..CraftingWindow2.descDataCount)
--	for idx, val in pairs(CraftingWindow2.descData) do
--		if (idx <= CraftingWindow2.descDataCount) then
--			local name = GetStringFromTid(tonumber(val))
--			Debug.Print(L"descData["..idx..L"]="..name..L" ("..val..L")")
--		end
--	end

--	Debug.Print("buttonCount="..CraftingWindow2.buttonCount)
--	for idx, val in pairs(CraftingWindow2.buttonIDs) do
--		if (idx <= CraftingWindow2.buttonCount) then
--			Debug.Print(L"buttonIDs["..idx..L"]="..val)
--		end
--	end

--	Debug.Print("stringCount="..CraftingWindow2.stringDataCount)
--	for idx, val in pairs(CraftingWindow2.stringData) do
--		Debug.Print(L"stringData["..idx..L"]="..val)
--	end

	UOBuildTableFromCSV ("Data/GameData/"..CraftingWindow.CSVFilenames[CraftingWindow.CraftingType], "Recipes")
	CraftingWindow2.findRecipeRecord()
	CraftingWindow2.parseTIDs()

--	Debug.Print("icon for CraftingWindow2:"..CraftingWindow2.recipeRec["GumpPic"])
	-- Object 0 means no picture
	if CraftingWindow2.recipeRec["GumpPic"] ~= 0 then
		local name, x, y, scale, newWidth, newHeight = RequestTileArt(CraftingWindow2.recipeRec["GumpPic"], 55, 55)
		CraftingWindow2.RequestedTileArt[#CraftingWindow2.RequestedTileArt + 1] = name
		DynamicImageSetTextureDimensions(SystemData.ActiveWindow.name.."Icon", newWidth, newHeight)
		WindowSetDimensions(SystemData.ActiveWindow.name.."Icon", newWidth, newHeight)
		DynamicImageSetTexture(SystemData.ActiveWindow.name.."Icon", name, 0, 0 )
		DynamicImageSetTextureScale(SystemData.ActiveWindow.name.."Icon", scale)
	end

	ButtonSetText(SystemData.ActiveWindow.name.."ActionButton1", L"MAKE NOW")		-- special (based on recipe) (10000)

	if (CraftingWindow2.buttonIDs[2] == 0) then
		WindowSetFontAlpha( SystemData.ActiveWindow.name.."ActionButton1", 0.5 )
	end

	ButtonSetText(SystemData.ActiveWindow.name.."ActionButton2", L"BACK")			-- 9999

	LabelSetText(SystemData.ActiveWindow.name.."Label1", CraftingWindow2.parsedText[1])
	LabelSetText(SystemData.ActiveWindow.name.."Label2", CraftingWindow2.parsedText[2])
	LabelSetText(SystemData.ActiveWindow.name.."Label2.5", CraftingWindow2.parsedText[2.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label3", CraftingWindow2.parsedText[3])
	LabelSetText(SystemData.ActiveWindow.name.."Label3.5", CraftingWindow2.parsedText[3.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label4", CraftingWindow2.parsedText[4])
	LabelSetText(SystemData.ActiveWindow.name.."Label4.5", CraftingWindow2.parsedText[4.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label5", CraftingWindow2.parsedText[5])
	LabelSetText(SystemData.ActiveWindow.name.."Label5.5", CraftingWindow2.parsedText[5.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label6", CraftingWindow2.parsedText[6])
	LabelSetText(SystemData.ActiveWindow.name.."Label6.5", CraftingWindow2.parsedText[6.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label7", CraftingWindow2.parsedText[7])
	LabelSetText(SystemData.ActiveWindow.name.."Label7.5", CraftingWindow2.parsedText[7.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label8", CraftingWindow2.parsedText[8])
	LabelSetText(SystemData.ActiveWindow.name.."Label8.5", CraftingWindow2.parsedText[8.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label9", CraftingWindow2.parsedText[9])
	LabelSetText(SystemData.ActiveWindow.name.."Label9.5", CraftingWindow2.parsedText[9.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label10", CraftingWindow2.parsedText[10])
	LabelSetText(SystemData.ActiveWindow.name.."Label10.5", CraftingWindow2.parsedText[10.5])
	LabelSetText(SystemData.ActiveWindow.name.."Label11", CraftingWindow2.parsedText[11])
	LabelSetText(SystemData.ActiveWindow.name.."Label12", CraftingWindow2.parsedText[12])
	LabelSetText(SystemData.ActiveWindow.name.."Label13", CraftingWindow2.parsedText[13])
	LabelSetText(SystemData.ActiveWindow.name.."Label14", CraftingWindow2.parsedText[14])
	LabelSetText(SystemData.ActiveWindow.name.."Label15", CraftingWindow2.parsedText[15])

end

function CraftingWindow2.SetIcon(window, obj)
	local name, x, y, scale, newWidth, newHeight = RequestTileArt(obj, 55, 55)
	CraftingWindow2.RequestedTileArt[#CraftingWindow2.RequestedTileArt + 1] = name
	DynamicImageSetTextureDimensions(window, newWidth, newHeight)
	WindowSetDimensions(window, newWidth, newHeight)		
	DynamicImageSetTexture(window, name, 0, 0 )
	
	DynamicImageSetTextureScale(window, scale)
end

function CraftingWindow2.findRecipeRecord()
	recipeRec = {}
	for recipeIdx, recipeRec in pairs(WindowData.Recipes) do
		if (CraftingWindow2.recipeID == recipeRec["RecipeID"]) then
			CraftingWindow2.recipeRec = recipeRec
			break
		end
	end
end

function CraftingWindow2.MakeMaterialString(matIdx)
	local str1 = L""
	local str2 = L""
	local matClass = "MaterialClass"..matIdx
	local matAmount = "SucceedConsume"..matIdx
	local matHue = "CopyHue"..matIdx
	local matNameIdx = 7 + matIdx

	if (CraftingWindow2.colorable) then
	-- skip one more line for "The item retains the color of this material"
		matNameIdx = matNameIdx + 1
	end

	if (CraftingWindow2.recipeRec["GumpTID"] == 1044458 or CraftingWindow2.recipeRec["GumpTID"] == 1044459) then
	-- "cut-up cloth" and "combine cloth" use an extra string
		matNameIdx = matNameIdx + 1
	end

	if (CraftingWindow2.recipeRec["Exceptional"] ~= 0) then
	-- skip one more line for "This item may hold its maker's mark"
		matNameIdx = matNameIdx + 1
	end

	if (CraftingWindow2.recipeRec["SecondarySkill"] ~= 0) then
	-- skip one more line for secondary skill name
		matNameIdx = matNameIdx + 1
	end

	if (CraftingWindow.CraftingType == 10 or CraftingWindow.CraftingType == 11) then
	-- skip one more line for special skill notice (glassblowing or masonry)
		matNameIdx = matNameIdx + 1
	end
	
	if (CraftingWindow2.recipeRec[matClass] ~= 0) then
		str1 = GetStringFromTid(tonumber(CraftingWindow2.descData[matNameIdx]))
		str2 = L""..CraftingWindow2.recipeRec[matAmount]
		-- padding to make colums line up:
		if (CraftingWindow2.recipeRec[matAmount] < 100) then
			str2 = L"  "..str2
			if (CraftingWindow2.recipeRec[matAmount] < 10) then
				str2 = L"  "..str2
			end
		end
		if (CraftingWindow2.recipeRec[matHue] == 1) then
			str2 = str2..L"*"
		end
	end
	
	-- Super kludgey fix for DT 10181, but it's only for a very, very specific case...
	if CraftingWindow2.recipeRec["GumpTID"] == 1073465 and matIdx == 3 then
		str1 = GetStringFromTid( tonumber( CraftingWindow2.descData[8] ) )
	end
	
	return str1,str2	
end

function CraftingWindow2.parseTIDs()
	local noRecipe = false
	for idx, val in pairs(CraftingWindow2.descData) do
	-- Check for "You have not learned this recipe." in TIDs from server
		if (tonumber(val) == 1073620 and idx <= CraftingWindow2.descDataCount) then
			noRecipe = true
		end
	end

	if (CraftingWindow2.recipeRec["CopyHue1"] ~= 0 or CraftingWindow2.recipeRec["CopyHue2"] ~= 0 or CraftingWindow2.recipeRec["CopyHue3"] ~= 0 or 
		CraftingWindow2.recipeRec["CopyHue4"] ~= 0 or CraftingWindow2.recipeRec["CopyHue5"] ~= 0) then
		CraftingWindow2.colorable = true
	else
		CraftingWindow2.colorable = false
	end

	-- pre-clear all strings, in case some are not set
	for i=1, 15 do
		CraftingWindow2.parsedText[i] = L" "
	end

	--"Item <name>"
	CraftingWindow2.parsedText[1] = GetStringFromTid(tonumber(CraftingWindow2.descData[1]))..L"   "..GetStringFromTid(CraftingWindow2.recipeRec["GumpTID"])
	if (CraftingWindow2.recipeRec["Exceptional"] == 1) then
		--"Success Chance: <#>"
		CraftingWindow2.parsedText[2] = GetStringFromTid(tonumber(CraftingWindow2.descData[CraftingWindow2.descDataCount-1]))
		CraftingWindow2.parsedText[2.5] = CraftingWindow2.stringData[CraftingWindow2.stringDataCount-1]
		--"Exceptional Chance: <#>"
		CraftingWindow2.parsedText[3] = GetStringFromTid(tonumber(CraftingWindow2.descData[CraftingWindow2.descDataCount]))
		CraftingWindow2.parsedText[3.5] = CraftingWindow2.stringData[CraftingWindow2.stringDataCount]
	else
		--"Success Chance: <#>"
		CraftingWindow2.parsedText[2] = GetStringFromTid(tonumber(CraftingWindow2.descData[CraftingWindow2.descDataCount]))
		CraftingWindow2.parsedText[2.5] = CraftingWindow2.stringData[CraftingWindow2.stringDataCount]
		--"Exceptional Chance: <#>"
		CraftingWindow2.parsedText[3] = L" "
		CraftingWindow2.parsedText[3.5] = L" "
	end
	--"<Skill required>: <#>"
	if (CraftingWindow2.skillTIDs[CraftingWindow2.recipeRec["Skill"]]) then
		CraftingWindow2.parsedText[4] = GetStringFromTid(CraftingWindow2.skillTIDs[tonumber(CraftingWindow2.recipeRec["Skill"])])
		CraftingWindow2.parsedText[4.5] = CraftingWindow2.stringData[1]
	else
		CraftingWindow2.parsedText[4] = L" "
		CraftingWindow2.parsedText[4.5] = L" "
	end
	--"<2nd Skill required>: <#>"
	if (CraftingWindow2.skillTIDs[CraftingWindow2.recipeRec["SecondarySkill"]] and
		tonumber(CraftingWindow2.recipeRec["SecondarySkill"]) ~= 0) then
		CraftingWindow2.parsedText[5] = GetStringFromTid(CraftingWindow2.skillTIDs[tonumber(CraftingWindow2.recipeRec["SecondarySkill"])])
		CraftingWindow2.parsedText[5.5] = CraftingWindow2.stringData[2]
	else
		CraftingWindow2.parsedText[5] = L" "
		CraftingWindow2.parsedText[5.5] = L" "
	end
	--"<material X>: <#>"
	CraftingWindow2.parsedText[6], CraftingWindow2.parsedText[6.5]  = CraftingWindow2.MakeMaterialString(1)
	CraftingWindow2.parsedText[7], CraftingWindow2.parsedText[7.5] = CraftingWindow2.MakeMaterialString(2)
	CraftingWindow2.parsedText[8], CraftingWindow2.parsedText[8.5] = CraftingWindow2.MakeMaterialString(3)
	CraftingWindow2.parsedText[9], CraftingWindow2.parsedText[9.5] = CraftingWindow2.MakeMaterialString(4)
	CraftingWindow2.parsedText[10], CraftingWindow2.parsedText[10.5] = CraftingWindow2.MakeMaterialString(5)

	curLine = 11

	if (CraftingWindow2.recipeRec["GumpTID"] == 1044458) then
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(1044460)
		curLine = curLine + 1
	elseif (CraftingWindow2.recipeRec["GumpTID"] == 1044459) then
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(1044461)
		curLine = curLine + 1
	end

	if (CraftingWindow.CraftingType == 10 or CraftingWindow.CraftingType == 11) then
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(tonumber(CraftingWindow2.descData[6]))
		curLine = curLine + 1
	end

	if (CraftingWindow2.recipeRec["Exceptional"] == 1) then
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(1044059)
		curLine = curLine + 1
	end

	if (CraftingWindow2.colorable) then
	-- * The item retains the color of this material
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(1044152)
		curLine = curLine + 1
	end

	if (CraftingWindow2.recipeRec["Service"] == 64) then
	-- * Requires the "Samurai Empire" expansion
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(1063363)
		curLine = curLine + 1
	elseif (CraftingWindow2.recipeRec["Service"] == 128) then
	-- * Requires the "Mondain's Legacy" expansion
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(1072651)
		curLine = curLine + 1
	end

	if (noRecipe) then
	-- "You have not learned this recipe."
		CraftingWindow2.parsedText[curLine] = GetStringFromTid(1073620)
		curLine = curLine + 1
	end

end

function CraftingWindow2.OnActionClicked()
	local buttonNum = WindowGetId(SystemData.ActiveWindow.name)

	-- Special-case buttons:
	if (buttonNum == 10000) then
		if (CraftingWindow2.buttonIDs[2] == 0) then
			return
		else
			buttonNum = CraftingWindow2.buttonIDs[2]
		end
	end

	CraftingWindow2.OnDefaultClicked(buttonNum)
	CraftingWindow2.DestroyWindow(CraftingWindow2.windowName)
end

function CraftingWindow2.SendServerButtonInfo(buttonNumber, window)
	UO_GenericGump.broadcastButtonPress( buttonNumber, window )
end

function CraftingWindow2.OnDefaultClicked(buttonNum)
	CraftingWindow2.SendServerButtonInfo(buttonNum, CraftingWindow2)
end

function CraftingWindow2.Shutdown()
	if CraftingWindow2.RequestedTileArt then
		for _, art in pairs( CraftingWindow2.RequestedTileArt ) do
			ReleaseTileArt( art )
		end
	end

	if CraftingWindow2.windowName and DoesWindowNameExist(SystemData.ActiveWindow.name) then
		WindowUtils.SaveWindowPosition(SystemData.ActiveWindow.name, false, "CraftingWindow")
	end
end

function CraftingWindow2.DestroyWindow(myWindowName)
	if DoesWindowNameExist(myWindowName) then
		WindowUtils.SaveWindowPosition(myWindowName, false, "CraftingWindow")
		DestroyWindow(myWindowName)
	end
	UOUnloadCSVTable("Recipes")
	CraftingWindow2.windowName = nil
end
