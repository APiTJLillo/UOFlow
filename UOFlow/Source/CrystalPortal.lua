----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

CrystalPortal = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

CrystalPortal.WindowName = "CrystalPortal"

CrystalPortal.Trammel = {}
CrystalPortal.Trammel.Dungeons = {
{name=L"Blighted Grove"; command=L"grove"; texture="grove";},
{name=L"Covetous"; command=L"covetous"; texture="covetous";},
{name=L"Deceit"; command=L"deceit"; texture="deceit";},
{name=L"Despise"; command=L"despise"; texture="despise";},
{name=L"Destard"; command=L"destard"; texture="destard";},
{name=L"Ice"; command=L"ice"; texture="ice";},
{name=L"Fire"; command=L"fire"; texture="fire";},
{name=L"Hythloth"; command=L"hythloth"; texture="hythloth";},
{name=L"Orc Cave"; command=L"orc"; texture="orccave";},
{name=L"Painted Caves"; command=L"caves"; texture="caves";},
{name=L"Palace of Paroxysmus"; command=L"palace"; texture="palace";},
{name=L"Prism of Light"; command=L"prism"; texture="prism";},
{name=L"Sanctuary"; command=L"sanctuary"; texture="sanctuary";},
{name=L"Shame"; command=L"shame"; texture="shame";},
{name=L"Wind"; command=L"wind"; texture="wind_dung";},
{name=L"Wrong"; command=L"wrong"; texture="wrong";},
{name=L"Doom"; command=L"doom"; texture="doom";},
{name=L"The Citadel"; command=L"citadel"; texture="citadel";},
{name=L"Fan Dancer Dojo"; command=L"fandancer"; texture="fandancer";},
{name=L"Yomotsu Mines"; command=L"mines"; texture="yomotsu";},
{name=L"Bedlam"; command=L"bedlam"; texture="bedlam";},
{name=L"The Labyrinth"; command=L"labyrinth"; texture="labyrinth";},
{name=L"Underworld"; command=L"underworld"; texture="underworld";},
{name=L"Tomb of the Kings"; command=L"abyss"; texture="abyss";},
}

CrystalPortal.Trammel.Moongates = {
{name=L"Britain"; command=L"britain"; texture="britain_moon";},
{name=L"Haven"; command=L"haven"; texture="haven_moon";},
{name=L"Jhelom"; command=L"jhelom"; texture="jhelom_moon";},
{name=L"Magincia"; command=L"magincia"; texture="magincia_moon";},
{name=L"Minoc"; command=L"minoc"; texture="minoc_moon";},
{name=L"Moonglow"; command=L"moonglow"; texture="moonglow_moon";},
{name=L"Skara Brae"; command=L"skara"; texture="skara_moon";},
{name=L"Trinsic"; command=L"trinsic"; texture="trinsic_moon";},
{name=L"Yew"; command=L"yew"; texture="yew_moon";},
{name=L"Compassion"; command=L"compassion"; texture="compassion";},
{name=L"Honesty"; command=L"honesty"; texture="honesty";},
{name=L"Honor"; command=L"honor"; texture="honor";},
{name=L"Humility"; command=L"humility"; texture="humility";},
{name=L"Justice"; command=L"justice"; texture="justice";},
{name=L"Sacrifice"; command=L"sacrifice"; texture="sacrifice";},
{name=L"Spirituality"; command=L"spirituality"; texture="spirituality";},
{name=L"Valor"; command=L"valor"; texture="valor";},
{name=L"Chaos"; command=L"chaos"; texture="chaos";},
{name=L"Luna"; command=L"luna"; texture="luna_moon";},
{name=L"Umbra"; command=L"umbra"; texture="umbra_moon";},
{name=L"Isamu Jima"; command=L"isamu"; texture="isamu";},
{name=L"Makoto Jima"; command=L"makoto"; texture="makoto";},
{name=L"Homare Jima"; command=L"homare"; texture="homare";},
{name=L"Royal City"; command=L"termur"; texture="royal_moon";},
{name=L"Valley of Eodon"; command=L"eodon"; texture="britain_moon";},
}
CrystalPortal.Trammel.Banks = {
{name=L"Britain"; command=L"britain"; texture="britain";},
{name=L"Buccaneer's Den"; command=L"bucs"; texture="bucsden";},
{name=L"Cove"; command=L"cove"; texture="cove";},
{name=L"Delucia"; command=L"delucia";  texture="delucia";},
{name=L"Haven"; command=L"haven"; texture="haven";},
{name=L"Jhelom"; command=L"jhelom"; texture="jhelom";},
{name=L"Magincia"; command=L"magincia"; texture="magincia";},
{name=L"Minoc"; command=L"minoc"; texture="minoc";},
{name=L"Moonglow"; command=L"moonglow"; texture="moonglow";},
{name=L"Nujel'm"; command=L"nujelm"; texture="nujelm";},
{name=L"Papua"; command=L"papua"; texture="papua";},
{name=L"Serpent's Hold"; command=L"serpent"; texture="serpent";},
{name=L"Skara Brae"; command=L"skara"; texture="skara";},
{name=L"Trinsic"; command=L"trinsic"; texture="trinsic";},
{name=L"Vesper"; command=L"vesper"; texture="vesper";},
{name=L"Wind"; command=L"wind"; texture="wind";},
{name=L"Yew"; command=L"yew"; texture="yew";},
{name=L"Luna"; command=L"luna"; texture="luna";},
{name=L"Umbra"; command=L"umbra"; texture="umbra";},
{name=L"Zento"; command=L"zento"; texture="zento";},
{name=L"Royal City"; command=L"termur"; texture="royal";},
{name=L"Gypsy Bank"; command=L"ilshenar"; texture="verlor";},
}

CrystalPortal.Felucca = {}
CrystalPortal.Felucca.Dungeons = {
{name=L"Blighted Grove"; command=L"grove"; texture="grove";},
{name=L"Covetous"; command=L"covetous"; texture="covetous";},
{name=L"Deceit"; command=L"deceit"; texture="deceit";},
{name=L"Despise"; command=L"despise"; texture="despise";},
{name=L"Destard"; command=L"destard"; texture="destard";},
{name=L"Ice"; command=L"ice"; texture="ice";},
{name=L"Fire"; command=L"fire"; texture="fire";},
{name=L"Hythloth"; command=L"hythloth"; texture="hythloth";},
{name=L"Orc Cave"; command=L"orc"; texture="orccave";},
{name=L"Painted Caves"; command=L"caves"; texture="caves";},
{name=L"Prism of Light"; command=L"prism"; texture="prism";},
{name=L"Shame"; command=L"shame"; texture="shame";},
{name=L"Sanctuary"; command=L"sanctuary"; texture="sanctuary";},
{name=L"Wind"; command=L"wind"; texture="wind_dung";},
{name=L"Wrong"; command=L"wrong"; texture="wrong";},
}
CrystalPortal.Felucca.Moongates = {
{name=L"Britain"; command=L"britain"; texture="britain_moon";},
{name=L"Buccaneer's Den"; command=L"bucs"; texture="bucsden_moon";},
{name=L"Jhelom"; command=L"jhelom"; texture="jhelom_moon";},
{name=L"Magincia"; command=L"magincia"; texture="magincia_moon";},
{name=L"Minoc"; command=L"minoc"; texture="minoc_moon";},
{name=L"Moonglow"; command=L"moonglow"; texture="moonglow_moon";},
{name=L"Skara Brae"; command=L"skara"; texture="skara_moon";},
{name=L"Trinsic"; command=L"trinsic"; texture="trinsic_moon";},
{name=L"Yew"; command=L"yew"; texture="yew_moon";},
}
CrystalPortal.Felucca.Banks = {
{name=L"Britain"; command=L"britain"; texture="britain";},
{name=L"Buccaneer's Den"; command=L"bucs";texture="bucsden";},
{name=L"Cove"; command=L"cove"; texture="cove";},
{name=L"Jhelom"; command=L"jhelom"; texture="jhelom";},
{name=L"Magincia"; command=L"magincia"; texture="magincia";},
{name=L"Minoc"; command=L"minoc"; texture="minoc";},
{name=L"Moonglow"; command=L"moonglow"; texture="moonglow";},
{name=L"Nujel'm"; command=L"nujelm"; texture="nujelm";},
{name=L"Ocllo"; command=L"ocllo"; texture="ocllo";},
{name=L"Serpent's Hold"; command=L"serpent"; texture="serpent";},
{name=L"Skara Brae"; command=L"skara"; texture="skara";},
{name=L"Trinsic"; command=L"trinsic"; texture="trinsic";},
{name=L"Vesper"; command=L"vesper"; texture="vesper";},
{name=L"Wind"; command=L"wind"; texture="wind";},
{name=L"Yew"; command=L"yew"; texture="yew";},
}

CrystalPortal.NoWind = false

CrystalPortal.LastSelection = 1
CrystalPortal.LastMap = 1
CrystalPortal.LastArea = 3

CrystalPortal.currentBase = {}
----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function CrystalPortal.Initialize()
	SnapUtils.SnappableWindows[CrystalPortal.WindowName] = true
	WindowUtils.RestoreWindowPosition(CrystalPortal.WindowName,true)
	WindowUtils.SetWindowTitle(CrystalPortal.WindowName,GetStringFromTid(1113945))  -- Crystal portal
	WindowSetDimensions(CrystalPortal.WindowName,  400,520)
	LabelSetText( CrystalPortal.WindowName .. "TrammelLabel", GetStringFromTid(1012000) ) -- L"Trammel"
	WindowSetId( CrystalPortal.WindowName .. "TrammelLabel", 1012000 )
	ButtonSetCheckButtonFlag( CrystalPortal.WindowName .. "TrammelButton", true )
	
	LabelSetText( CrystalPortal.WindowName .. "FeluccaLabel", GetStringFromTid(1012001) ) -- L"Felucca"
	WindowSetId( CrystalPortal.WindowName .. "FeluccaLabel", 1012001 )
	ButtonSetCheckButtonFlag( CrystalPortal.WindowName .. "FeluccaButton", true )
	
	LabelSetText( CrystalPortal.WindowName .. "DungeonLabel", GetStringFromTid(1075159) ) -- L"Dungeon"
	WindowSetId( CrystalPortal.WindowName .. "DungeonLabel", 1075159 )
	ButtonSetCheckButtonFlag( CrystalPortal.WindowName .. "DungeonButton", true )
	LabelSetText( CrystalPortal.WindowName .. "MoongateLabel", GetStringFromTid(1076082) ) -- L"Moongate"
	WindowSetId( CrystalPortal.WindowName .. "MoongateLabel", 1076082 )
	ButtonSetCheckButtonFlag( CrystalPortal.WindowName .. "MoongateButton", true )
	LabelSetText( CrystalPortal.WindowName .. "BankLabel", GetStringFromTid(1076117) ) -- L"Bank"
	WindowSetId( CrystalPortal.WindowName .. "BankLabel", 1076117 )
	ButtonSetCheckButtonFlag( CrystalPortal.WindowName .. "BankButton", true )
	
	LabelSetText( CrystalPortal.WindowName .. "DestLabel", GetStringFromTid(1012011) ) -- L"Destination"
	WindowSetId( CrystalPortal.WindowName .. "DestLabel", 1012011 )
	
	ButtonSetText(CrystalPortal.WindowName .. "Go", GetStringFromTid(3010006)) -- L"GO!"
	
	ButtonSetPressedFlag( CrystalPortal.WindowName .. "TrammelButton", true )
	ButtonSetPressedFlag( CrystalPortal.WindowName .. "BankButton", true )
	
	CrystalPortal.LastMap = Interface.LoadNumber( "CrystalPortalMap", 1 )
	CrystalPortal.LastArea = Interface.LoadNumber( "CrystalPortalArea", 3 )
	CrystalPortal.LastSelection = Interface.LoadNumber( "CrystalPortalSelection", 1 )
end

function CrystalPortal.Shutdown()
	SnapUtils.SnappableWindows[CrystalPortal.WindowName] = nil
	WindowUtils.SaveWindowPosition(CrystalPortal.WindowName)
	WindowSetShowing(CrystalPortal.WindowName,false)
	DestroyWindow(CrystalPortal.WindowName)
end

function CrystalPortal.OnShown()
	
	if (CrystalPortal.LastMap) then
		if (CrystalPortal.LastMap == 1) then
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "TrammelButton", true )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton", false )
		else
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "TrammelButton", false )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton", true )
		end
	end
	if (CrystalPortal.LastArea) then
		if (CrystalPortal.LastArea  ==  1) then
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "DungeonButton", true )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "MoongateButton", false )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "BankButton", false )
		elseif (CrystalPortal.LastArea  ==  2) then
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "DungeonButton", false )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "MoongateButton", true )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "BankButton", false )
		elseif (CrystalPortal.LastArea  ==  3) then
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "DungeonButton", false )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "MoongateButton", false )
			ButtonSetPressedFlag( CrystalPortal.WindowName .. "BankButton", true )
		end
	end
	CrystalPortal.CheckEnable()
	if (CrystalPortal.LastSelection) then
		ComboBoxSetSelectedMenuItem(CrystalPortal.WindowName .. "DestCombo", CrystalPortal.LastSelection)
	end
end

function CrystalPortal.CheckEnable()
	local lastName = ""
	local idx = ComboBoxGetSelectedMenuItem(CrystalPortal.WindowName .. "DestCombo")
	if idx ~= 0 and #CrystalPortal.currentBase > 0 then
		if (CrystalPortal.NoWind == true and idx >9) then
			idx = idx +1
		end
		lastName = CrystalPortal.currentBase[idx].name
	end
	
	ComboBoxClearMenuItems( CrystalPortal.WindowName .. "DestCombo" )
	local win = string.gsub(SystemData.ActiveWindow.name , "Button", "")
	win = string.gsub(win , "Label", "")
	
	if (win  ==  CrystalPortal.WindowName .. "Trammel") then
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "TrammelButton", true )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton", false )
	elseif (win  ==  CrystalPortal.WindowName .. "Felucca") then
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "TrammelButton", false )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton", true )
	end
	
	if (win  ==  CrystalPortal.WindowName .. "Dungeon") then
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "DungeonButton", true )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "MoongateButton", false )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "BankButton", false )
		
		
	elseif (win  ==  CrystalPortal.WindowName .. "Moongate") then
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "DungeonButton", false )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "MoongateButton", true )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "BankButton", false )
	elseif (win  ==  CrystalPortal.WindowName .. "Bank") then
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "DungeonButton", false )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "MoongateButton", false )
		ButtonSetPressedFlag( CrystalPortal.WindowName .. "BankButton", true )
	end
	
	local base
	
	if (ButtonGetPressedFlag( CrystalPortal.WindowName .. "TrammelButton")) then
		base = CrystalPortal.Trammel
	elseif (ButtonGetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton")) then
		base = CrystalPortal.Felucca
	end
	
	if (ButtonGetPressedFlag( CrystalPortal.WindowName .. "DungeonButton")) then
		base = base.Dungeons
	elseif (ButtonGetPressedFlag( CrystalPortal.WindowName .. "MoongateButton")) then
		base = base.Moongates
	elseif (ButtonGetPressedFlag( CrystalPortal.WindowName .. "BankButton")) then
		base = base.Banks
	end
	
	for i = 1, table.getn( base )do
		if (base[i] and base[i].name == L"Wind") then
			local serverId = WindowData.SkillsCSV[32].ServerId
			local skillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
			--local int = tonumber(WindowData.PlayerStatus["Intelligence"]) - tonumber(wstring.sub(CharacterSheet.StrDexIntBonus( "IncreaseInt" ),3,-2))
			if skillLevel < 71.5 then
				--base[i] =  nil
				CrystalPortal.NoWind = true
				continue
			end
		end
		if (base[i]) then
			ComboBoxAddMenuItem( CrystalPortal.WindowName .. "DestCombo", base[i].name )
		end
	end
	CrystalPortal.currentBase = base
	
	
	if lastName ~= "" then
		local found = false
		for i = 1, table.getn( base )do
			if (base[i] and base[i].name == lastName) then
				if (CrystalPortal.NoWind == true and i >9) then
					i = i +1
				end
				ComboBoxSetSelectedMenuItem(CrystalPortal.WindowName .. "DestCombo",i)
				found = true
				break
			end
		end
		if not found then
			ComboBoxSetSelectedMenuItem(CrystalPortal.WindowName .. "DestCombo", 1)
		end
	else
		ComboBoxSetSelectedMenuItem(CrystalPortal.WindowName .. "DestCombo", 1)
	end	
end

function CrystalPortal.GO()
	
	local finalstring = L""
	
	local idx = ComboBoxGetSelectedMenuItem(CrystalPortal.WindowName .. "DestCombo")
	if (idx == 0) then
		return
	end
	
	if (ButtonGetPressedFlag( CrystalPortal.WindowName .. "TrammelButton")) then
		base = CrystalPortal.Trammel
		CrystalPortal.LastMap = 1
	elseif (ButtonGetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton")) then
		base = CrystalPortal.Felucca
		finalstring = L"fel "
		CrystalPortal.LastMap = 2
	end
	Interface.SaveNumber( "CrystalPortalMap" , CrystalPortal.LastMap )
	
	if (ButtonGetPressedFlag( CrystalPortal.WindowName .. "DungeonButton")) then
		base = base.Dungeons
		if (CrystalPortal.NoWind == true and idx >9) then
			idx = idx +1
		end
		finalstring = finalstring .. L"dungeon " .. base[idx].command 
		CrystalPortal.LastArea = 1
	elseif (ButtonGetPressedFlag( CrystalPortal.WindowName .. "MoongateButton")) then
		base = base.Moongates
		finalstring = finalstring  .. base[idx].command .. L" moongate"
		CrystalPortal.LastArea = 2
	elseif (ButtonGetPressedFlag( CrystalPortal.WindowName .. "BankButton")) then
		base = base.Banks
		if (CrystalPortal.NoWind == true ) then
			if (idx >13 and ButtonGetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton")) then
				idx = idx +1
			elseif (idx >15 and ButtonGetPressedFlag( CrystalPortal.WindowName .. "TrammelButton")) then
				idx = idx +1
			end
		end
		finalstring = finalstring  .. base[idx].command .. L" mint"
		CrystalPortal.LastArea = 3
	end
	Interface.SaveNumber( "CrystalPortalArea" , CrystalPortal.LastArea )
	
	CrystalPortal.LastSelection = tonumber(idx)
	if (CrystalPortal.NoWind and CrystalPortal.LastArea ~= 2) then
		if (CrystalPortal.NoWind == true ) then
			if (idx >13 and ButtonGetPressedFlag( CrystalPortal.WindowName .. "FeluccaButton")) then
				CrystalPortal.LastSelection = CrystalPortal.LastSelection -1
			elseif (idx >15 and ButtonGetPressedFlag( CrystalPortal.WindowName .. "TrammelButton")) then
				CrystalPortal.LastSelection = CrystalPortal.LastSelection -1
			elseif (idx >9 and ButtonGetPressedFlag( CrystalPortal.WindowName .. "DungeonButton")) then
				CrystalPortal.LastSelection = CrystalPortal.LastSelection -1
			end
		end
		
	end
	Interface.SaveNumber( "CrystalPortalSelection" , CrystalPortal.LastSelection )	
	_channel = ChatSettings.Channels[ SystemData.ChatLogFilters.SAY ]
	SendChat( _channel, L"/say " .. finalstring )
	CrystalPortal.Toggle()
end

function CrystalPortal.LabelOnMouseOver()
	local windowName = SystemData.ActiveWindow.name
	local detailTID = WindowGetId(windowName)	
	
	local text = GetStringFromTid(detailTID)
	Tooltips.CreateTextOnlyTooltip(windowName, text)
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
	
end

function CrystalPortal.Toggle()
	local state = WindowGetShowing(CrystalPortal.WindowName)
	WindowSetShowing(CrystalPortal.WindowName, not state)
end