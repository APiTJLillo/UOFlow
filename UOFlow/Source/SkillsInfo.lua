
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

SkillsInfo = {}
SkillsInfo.DisplaySkill = 1

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

OFFSET_TITLE	= 1
OFFSET_DESC	= 2
OFFSET_REQ	= 3
OFFSET_DIRECT	= 4
OFFSET_INTER	= 5
OFFSET_AUTO	= 6
OFFSET_MORE	= 7
OFFSET_CLASS	= 8


TID_WINDOW_NAME	= 1078584
TID_REQUIRES	= 1078597
TID_DIRECT	= 1078598
TID_INTERACTIVE	= 1078599
TID_AUTOMATIC	= 1078600
TID_MORE	= 1078601
TID_REQ_NOTHING = 1078611

BIG_SPACER	= 8
SMALL_SPACER	= 4
WIDE_SPACER	= 10
WINDOW_WIDTH	= 580

-- Title, Description, Requires, Direct, Interactive, Automatic, More
local skill01 = {1002000, 1078612, 1078613, 0, 1078614, 1078615, 1078616, L"Alchemist"}	-- Alchemy
local skill02 = {1002004, 1078623, 0, 1078624, 0, 1078625, 1078626, L"Biologist"}		-- Anatomy
local skill03 = {1002007, 1078627, 0, 1078628, 0, 1078629, 1078630, L"Naturalist"}		-- Animal Lore
local skill04 = {1002010, 1078631, 0, 1078632, 0, 0, 1078633, L"Tamer"}			-- Animal Taming
local skill05 = {1002029, 1078634, 1078635, 0, 1078636, 0, 1078637, L"Archer"}		-- Archery
local skill06 = {1002034, 1078638, 0, 1078639, 0, 1078640, 1078641, L"Weapon Master"}		-- Arms Lore
local skill07 = {1002040, 1078642, 0, 1078643, 0, 0, 1078644, L"Beggar"}			-- Begging
local skill08 = {1044296, 1078645, 1078646, 0, 1078647, 0, 1078648, L"Blacksmith"}		-- Blacksmithy
local skill09 = {1044112, 1078649, 1078650, 0, 1078651, 0, 1078652, L"Samurai"}		-- Bushido
local skill10 = {1002050, 1078653, 1078654, 0, 1078655, 0, 1078656, L"Explorer"}		-- Camping
local skill11 = {1002054, 1078657, 1078658, 0, 1078659, 0, 1078660, L"Carpenter"}		-- Carpentry
local skill12 = {1002057, 1078661, 1078662, 0, 1078663, 0, 1078664, L"Cartographer"}		-- Cartography
local skill13 = {1044111, 1078665, 1078666, 0, 1078667, 0, 1078668, L"Paladin"}		-- Chivalry
local skill14 = {1002063, 1078669, 1078670, 0, 1078671, 0, 1078672, L"Chef"}		-- Cooking
local skill15 = {1002065, 1078673, 0, 1078674, 0, 0, 1078675, L"Scout"}			-- Detecting Hidden
local skill16 = {1044075, 1078676, 1078677, 1078678, 0, 0, 1078679, L"Demoralizer"}		-- Discordance
local skill17 = {1044076, 1078680, 0, 1078681, 0, 1078682, 1078683, L"Scholar"}		-- Evaluating Intelligence
local skill18 = {1002073, 1002074, 1078685, 0, 1078686, 0, 1078687, L"Fencer"}		-- Fencing
local skill19 = {1002076, 1078692, 1078693, 0, 1078694, 0, 1078695, L"Fisherman"}		-- Fishing
local skill20 = {1015156, 1078688, 1078689, 0, 1078690, 0, 1078691, L"Bowyer"}		-- Fletching
local skill21 = {1044110, 1078696, 0, 0, 0, 1078697, 1078698, L"Driven"}			-- Focus
local skill22 = {1002078, 1078699, 0, 1078700, 0, 0, 1078701, L"Detective"}			-- Forensic Evaluation
local skill23 = {1002082, 1078702, 0, 0, 1078703, 0, 1078704, L"Healer"}			-- Healing
local skill24 = {1002086, 1078705, 1078706, 0, 1078707, 0, 1078708, L"Shepherd"}		-- Herding
local skill25 = {1002088, 1078709, 0, 1078710, 0, 0, 1078711, L"Shade"}			-- Hiding
local skill26 =	{1079712, 1079715, 1095248, 0, 1079720, 0, 1079723, L"Artificer"}		-- Imbuing
local skill27 = {1002090, 1078712, 1078713, 1078714, 1078715, 1078716, 1078717, L"Scribe"}	-- Inscription
local skill28 = {1002094, 1078718, 0, 1078719, 0, 0, 1078720, L"Merchant"}			-- Item Identification
local skill29 = {1002097, 1078721, 1078722, 0, 1078723, 0, 1078724, L"Infiltrator"}		-- Lockpicking
local skill30 = {1002100, 1078725, 1078726, 0, 1078727, 1078728, 1078729, L"Lumberjack"}	-- Lumberjacking
local skill31 = {1002102, 1078730, 1078731, 0, 1078732, 0, 1078733, L"Armsman"}		-- Mace Fighting
local skill32 = {1002106, 1078734, 1078735, 0, 1078736, 0, 1078737, L"Mage"}		-- Magery
local skill33 = {1044086, 1078742, 0, 0, 0, 1078743, 1078744, L"Warder"}			-- Resisting Spells
local skill34 = {1044106, 1078738, 0, 1078739, 0, 1078740, 1078741, L"Stoic"}		-- Meditation
local skill35 = {1002111, 1078745, 1078746, 0, 1078747, 0, 1078748, L"Miner"}		-- Mining
local skill36 = {1002116, 1078749, 1078750, 0, 1078751, 0, 1078752, L"Bard"}		-- Musicianship
local skill37 = {1079711, 1079714, 1095247, 0, 1079719, 0, 1079722, L"Mystic"}		-- Mysticism
local skill38 = {1044109, 1078753, 1078754, 0, 1078755, 0, 1078756, L"Necromancer"}		-- Necromancy
local skill39 = {1044113, 1078757, 1078758, 0, 1078759, 0, 1078760, L"Ninja"}		-- Ninjitsu
local skill40 = {1002118, 1078761, 1078762, 0, 1078763, 0, 1078764, L"Duelist"}		-- Parrying
local skill41 = {1002120, 1078765, 1078766, 1078767, 0, 0, 1078768, L"Pacifier"}		-- Peacemaking
local skill42 = {1002122, 1078769, 1078770, 1078771, 0, 1078772, 1078773, L"Assassin"}	-- Poisoning
local skill43 = {1002125, 1078774, 1078775, 1078776, 0, 0, 1078777, L"Rouser"}		-- Provocation
local skill44 = {1002136, 1078778, 0, 1078779, 0, 0, 1078780, L"Trap Specialist"}			-- Remove Trap
local skill45 = {1002138, 1078781, 0, 0, 1078782, 0, 1078783, L"Spy"}			-- Snooping
local skill46 = {1044114, 1078784, 1078785, 0, 1078786, 0, 1078787, L"Arcanist"}		-- Spellweaving
local skill47 = {1002140, 1078788, 0, 1078789, 0, 1078790, 1078791, L"Medium"}		-- Spirit Speak
local skill48 = {1002142, 1078792, 0, 1078793, 0, 0, 1078794, L"Pickpocket"}			-- Stealing
local skill49 = {1044107, 1078795, 1078856, 1078796, 0, 1078805, 1078797, L"Rogue"}	-- Stealth
local skill50 = {1002151, 1078798, 1078799, 0, 1078800, 0, 1078801, L"Swordsman"}		-- Swordsmanship
local skill51 = {1044087, 1078802, 0, 0, 0, 1078803, 1078804, L"Tactician"}			-- Tactics
local skill52 = {1002155, 1078806, 1078807, 0, 1078808, 0, 1078809, L"Tailor"}		-- Tailoring
local skill53 = {1002160, 1078810, 0, 1078811, 0, 0, 1078812, L"Preagustator"}			-- Taste Identification
local skill54 = {1079713, 1079716, 1095249, 0, 1079721, 0, 1079724, L"Bladeweaver"}		-- Throwing
local skill55 = {1002162, 1078813, 1078814, 0, 1078815, 0, 1078816, L"Tinker"}		-- Tinkering
local skill56 = {1002165, 1078817, 0, 1078818, 0, 0, 1078819, L"Ranger"}			-- Tracking
local skill57 = {1002167, 1078820, 1078821, 0, 1078822, 0, 1078823, L"Veterinarian"}		-- Veterinary
local skill58 = {1002169, 1078824, 0, 0, 1078825, 0, 1078826, L"Wrestler"}			-- Wrestling


local skillInfo = {
	skill01,
	skill02,
	skill03,
	skill04,
	skill05,
	skill06,
	skill07,
	skill08,
	skill09,
	skill10,
	skill11,
	skill12,
	skill13,
	skill14,
	skill15,
	skill16,
	skill17,
	skill18,
	skill19,
	skill20,
	skill21,
	skill22,
	skill23,
	skill24,
	skill25,
	skill26,
	skill27,
	skill28,
	skill29,
	skill30,
	skill31,
	skill32,
	skill33,
	skill34,
	skill35,
	skill36,
	skill37,
	skill38,
	skill39,
	skill40,
	skill41,
	skill42,
	skill43,
	skill44,
	skill45,
	skill46,
	skill47,
	skill48,
	skill49,
	skill50,
	skill51,
	skill52,
	skill53,
	skill54,
	skill55,
	skill56,
	skill57,
	skill58
}


----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function SkillsInfo.Initialize()
	WindowClearAnchors("SkillsInfo")
	WindowAddAnchor( "SkillsInfo", "topright", "SkillsWindow", "topleft", 0, 0 )
	WindowUtils.RestoreWindowPosition("SkillsInfo")
end

function SkillsInfo.Shutdown()
	WindowUtils.SaveWindowPosition("SkillsInfo")
end

function SkillsInfo.ClearGump()
	local this = "SkillsInfo"
	WindowUtils.SetWindowTitle(this, L" ")
	WindowUtils.ScrollToElementInScrollWindow( this .. "SkillDesc", "SkillInfoTextWindow", "SkillInfoTextWindowScrollChildText" )
	WindowSetDimensions("SkillInfoTextWindowScrollChildText", 330, 0  )
	ScrollWindowUpdateScrollRect( "SkillInfoTextWindow" )
	
	if (DoesWindowNameExist(this .. "SkillDesc")) then
		DestroyWindow(this .. "SkillDesc")
	end
	if (DoesWindowNameExist(this .. "RequirementsLbLTitle")) then
		DestroyWindow(this .. "RequirementsLbLTitle")
	end
	if (DoesWindowNameExist(this .. "RequirementsLbLDescription")) then
		DestroyWindow(this .. "RequirementsLbLDescription")
	end
	if (DoesWindowNameExist(this .. "DirectLbLTitle")) then
		DestroyWindow(this .. "DirectLbLTitle")
	end
	if (DoesWindowNameExist(this .. "DirectLbLDescription")) then
		DestroyWindow(this .. "DirectLbLDescription")
	end
	if (DoesWindowNameExist(this .. "InterLbLTitle")) then
		DestroyWindow(this .. "InterLbLTitle")
	end
	if (DoesWindowNameExist(this .. "InterLbLDescription")) then
		DestroyWindow(this .. "InterLbLDescription")
	end
	if (DoesWindowNameExist(this .. "AutoLbLTitle")) then
		DestroyWindow(this .. "AutoLbLTitle")
	end
	if (DoesWindowNameExist(this .. "AutoLbLDescription")) then
		DestroyWindow(this .. "AutoLbLDescription")
	end
	if (DoesWindowNameExist(this .. "TtleLbLTitle")) then
		DestroyWindow(this .. "TtleLbLTitle")
	end
	if (DoesWindowNameExist(this .. "TtleLbLDescription")) then
		DestroyWindow(this .. "TtleLbLDescription")
	end
	if (DoesWindowNameExist(this .. "MoreLbLTitle")) then
		DestroyWindow(this .. "MoreLbLTitle")
	end
	if (DoesWindowNameExist(this .. "MoreLbLDescription")) then
		DestroyWindow(this .. "MoreLbLDescription")
	end
	if (DoesWindowNameExist(this .. "TrainLbLTitle")) then
		DestroyWindow(this .. "TrainLbLTitle")
	end
	if (DoesWindowNameExist(this .. "TrainLbLDescription")) then
		DestroyWindow(this .. "TrainLbLDescription")
	end
	if (DoesWindowNameExist(this .. "SatLbLTitle")) then
		DestroyWindow(this .. "SatLbLTitle")
	end
	if (DoesWindowNameExist(this .. "SatLbLDescription")) then
		DestroyWindow(this .. "SatLbLDescription")
	end
	if (DoesWindowNameExist(this .. "GolLbLTitle")) then
		DestroyWindow(this .. "GolLbLTitle")
	end
	if (DoesWindowNameExist(this .. "GolLbLDescription")) then
		DestroyWindow(this .. "GolLbLDescription")
	end
	
end

function lines(str)
  local t = {}
  local function helper(line) table.insert(t, line) return "" end
  helper((str:gsub("(.-)\r?\n", helper)))
  return t
end

function SkillsInfo.UpdateGump(DisplaySkill )
	SkillsInfo.ClearGump()
	local this = "SkillsInfo"
	
	local index = DisplaySkill
	WindowSetShowing(this, true)
	
	
	-- Title, Description, Requires, Direct, Interactive, Automatic, More
	
	local info = skillInfo[index]
	local title = info[OFFSET_TITLE]
	local desc = info[OFFSET_DESC]
	local req = info[OFFSET_REQ]
	local direct = info[OFFSET_DIRECT]
	local inter = info[OFFSET_INTER]
	local auto = info[OFFSET_AUTO]
	local ttle = info[OFFSET_CLASS]
	local path = "./UserInterface/"..SystemData.Settings.Interface.customUiName.."/SkillTraining/"
	if (SystemData.Settings.Language.type ~= SystemData.Settings.Language.LANGUAGE_ENU) then
		path = path .. "ENU/"
	elseif (SystemData.Settings.Language.type ~= SystemData.Settings.Language.LANGUAGE_JPN) then
		path = path .. "JPN/"
	elseif (SystemData.Settings.Language.type ~= SystemData.Settings.Language.LANGUAGE_CHINESE_TRADITIONAL) then
		path = path .. "CHT/"
	end
	local train = LoadTextFile(path .. "skill" .. index .. ".txt")
	local more = 0 --info[OFFSET_MORE]
	
	WindowUtils.SetWindowTitle(this, WindowUtils.translateMarkup( GetStringFromTid(title)))
	
	local totalH = 0
	
	CreateWindowFromTemplate( this .. "SkillDesc", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
	LabelSetText( this .. "SkillDesc", GetStringFromTid(desc)  )
	WindowAddAnchor( this .. "SkillDesc", "topleft", "SkillInfoTextWindowScrollChildText", "topleft", 0, 0 )
	
	local x, y = WindowGetDimensions( this .. "SkillDesc")
	totalH = totalH + y
	
	CreateWindowFromTemplate(  this .. "RequirementsLbLTitle", "LabelTitle", "SkillInfoTextWindowScrollChildText" )
	WindowAddAnchor( this .. "RequirementsLbLTitle", "bottomleft",  this .. "SkillDesc", "topleft", 0, 10 )
	local rr = wstring.gsub(GetStringFromTid(TID_REQUIRES), L" ~1_val~", L"")
	LabelSetText( this .. "RequirementsLbLTitle", rr  )
	
	local x, y = WindowGetDimensions( this .. "RequirementsLbLTitle")
	totalH = totalH + y + 10
	
	CreateWindowFromTemplate(  this .. "RequirementsLbLDescription", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
	WindowAddAnchor( this .. "RequirementsLbLDescription", "bottomleft",  this .. "RequirementsLbLTitle", "topleft", 0, 8 )
	
	if req == 0 then
		req = TID_REQ_NOTHING
	end
	LabelSetText( this .. "RequirementsLbLDescription", WindowUtils.translateMarkup( GetStringFromTid(req)) )
	
	local x, y = WindowGetDimensions( this .. "RequirementsLbLDescription")
	totalH = totalH + y + 8
	
	local lastLBL =  this .. "RequirementsLbLDescription"
	
	-- "Direct Usage" (Optional)
	if direct ~= 0 then
		CreateWindowFromTemplate(  this .. "DirectLbLTitle", "LabelTitle", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "DirectLbLTitle", "bottomleft", lastLBL, "topleft", 0, 10 )
		LabelSetText( this .. "DirectLbLTitle", WindowUtils.translateMarkup( GetStringFromTid(TID_DIRECT))  )
		
		local x, y = WindowGetDimensions( this .. "DirectLbLTitle")
		totalH = totalH + y + 10
	
		CreateWindowFromTemplate(  this .. "DirectLbLDescription", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "DirectLbLDescription", "bottomleft",  this .. "DirectLbLTitle", "topleft", 0, 8 )
		LabelSetText( this .. "DirectLbLDescription", WindowUtils.translateMarkup( GetStringFromTid(direct)) )
		lastLBL =  this .. "DirectLbLDescription"
		
		local x, y = WindowGetDimensions( this .. "DirectLbLDescription")
		totalH = totalH + y + 8
	end
	
	-- "Interactive Usage" (Optional)
	if inter ~= 0 then
		CreateWindowFromTemplate(  this .. "InterLbLTitle", "LabelTitle", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "InterLbLTitle", "bottomleft", lastLBL, "topleft", 0, 10 )
		LabelSetText( this .. "InterLbLTitle", WindowUtils.translateMarkup( GetStringFromTid(TID_INTERACTIVE))  )
		
		local x, y = WindowGetDimensions( this .. "InterLbLTitle")
		totalH = totalH + y + 10
		
		CreateWindowFromTemplate(  this .. "InterLbLDescription", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "InterLbLDescription", "bottomleft",  this .. "InterLbLTitle", "topleft", 0, 8 )
		LabelSetText( this .. "InterLbLDescription", WindowUtils.translateMarkup( GetStringFromTid(inter)) )
		lastLBL =  this .. "InterLbLDescription"
		
		local x, y = WindowGetDimensions( this .. "InterLbLDescription")
		totalH = totalH + y + 8
	end
	
	-- "Automatic Usage" (Optional)
	if auto ~= 0 then
		CreateWindowFromTemplate(  this .. "AutoLbLTitle", "LabelTitle", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "AutoLbLTitle", "bottomleft", lastLBL, "topleft", 0, 10 )
		LabelSetText( this .. "AutoLbLTitle", WindowUtils.translateMarkup( GetStringFromTid(TID_AUTOMATIC))  )
		
		local x, y = WindowGetDimensions( this .. "AutoLbLTitle")
		totalH = totalH + y + 10
		
		CreateWindowFromTemplate(  this .. "AutoLbLDescription", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "AutoLbLDescription", "bottomleft",  this .. "AutoLbLTitle", "topleft", 0, 8 )
		LabelSetText( this .. "AutoLbLDescription", WindowUtils.translateMarkup( GetStringFromTid(auto)) )
		lastLBL =  this .. "AutoLbLDescription"
		
		local x, y = WindowGetDimensions( this .. "AutoLbLDescription")
		totalH = totalH + y + 8
	end
	
	-- "Title Unlocked" (Optional)
	if ttle then
		CreateWindowFromTemplate(  this .. "TtleLbLTitle", "LabelTitle", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "TtleLbLTitle", "bottomleft", lastLBL, "topleft", 0, 10 )
		LabelSetText( this .. "TtleLbLTitle", GetStringFromTid(1155271) .. L" " )
		
		local x, y = WindowGetDimensions( this .. "TtleLbLTitle")
		totalH = totalH + y + 10
		
		CreateWindowFromTemplate(  this .. "TtleLbLDescription", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "TtleLbLDescription", "bottomleft",  this .. "TtleLbLTitle", "topleft", 0, 8 )
		LabelSetText( this .. "TtleLbLDescription", ttle )
		lastLBL =  this .. "TtleLbLDescription"
		
		local x, y = WindowGetDimensions( this .. "TtleLbLDescription")
		totalH = totalH + y + 8
	end
	
	-- "Training Methods" (Optional)
	if train then
		local train = lines(WStringToString(train))

		train = StringToWString(train)
		
		CreateWindowFromTemplate(  this .. "TrainLbLTitle", "LabelTitle", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "TrainLbLTitle", "bottomleft", lastLBL, "topleft", 0, 20 )
		LabelSetText( this .. "TrainLbLTitle", GetStringFromTid(1155272) )
		
		local x, y = WindowGetDimensions( this .. "TrainLbLTitle")
		totalH = totalH + y + 20
		
		CreateWindowFromTemplate(  this .. "TrainLbLDescription", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "TrainLbLDescription", "bottomleft",  this .. "TrainLbLTitle", "topleft", 0, 8 )
		LabelSetText( this .. "TrainLbLDescription", train )
		lastLBL =  this .. "TrainLbLDescription"
		
		local x, y = WindowGetDimensions( this .. "TrainLbLDescription")
		totalH = totalH + y + 8
		
		
	end
	
	-- "More" (Optional)
	if more ~= 0 then
		CreateWindowFromTemplate(  this .. "MoreLbLTitle", "LabelTitle", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "MoreLbLTitle", "bottomleft", lastLBL, "topleft", 0, 10 )
		LabelSetText( this .. "MoreLbLTitle", WindowUtils.translateMarkup( GetStringFromTid(TID_MORE))  )
		
		local x, y = WindowGetDimensions( this .. "MoreLbLTitle")
		totalH = totalH + y + 10
		
		CreateWindowFromTemplate(  this .. "MoreLbLDescription", "LabelDescription", "SkillInfoTextWindowScrollChildText" )
		WindowAddAnchor( this .. "MoreLbLDescription", "bottomleft",  this .. "MoreLbLTitle", "topleft", 0, 8 )
		LabelSetText( this .. "MoreLbLDescription", WindowUtils.translateMarkup( GetStringFromTid(more)) )
		lastLBL =  this .. "MoreLbLDescription"
		
		local x, y = WindowGetDimensions( this .. "MoreLbLDescription")
		totalH = totalH + y + 8
	end
	
	
	
	local Width, Height = WindowGetDimensions("SkillInfoTextWindowScrollChildText")
	
	WindowSetDimensions("SkillInfoTextWindowScrollChildText", Width, totalH  )
	ScrollWindowUpdateScrollRect( "SkillInfoTextWindow" )
end