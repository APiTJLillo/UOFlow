
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

SettingsWindow = {}

-- System Messages
SettingsWindow.IGNORE_LIST_ALL = 0
SettingsWindow.IGNORE_LIST_CONF	= 1
SettingsWindow.ignoreListType	= SettingsWindow.IGNORE_LIST_ALL

SettingsWindow.Modes = {}
SettingsWindow.Modes.Graphics = 1 
SettingsWindow.Modes.KeyBindings = 2 
SettingsWindow.Modes.Options = 5
SettingsWindow.Modes.NUM_MODES = 11

SettingsWindow.Modes.windows = { "SettingsGraphicsWindow", 
								"SettingsKeyBindingsWindow", 
								"SettingsSoundWindow", 
								"SettingsOptionsWindow", 
								"SettingsLegacyWindow", 
								"SettingsProfanityWindow", 
								"SettingsKeyDefaultWindow",
								"OverheadTextSettingsWindow",
								"ContainersSettingsWindow",
								"HealthbarsSettingsWindow",
								"SettingsMobilesOnScreen",
								}

SettingsWindow.LegacyBackpackStyle = {}
SettingsWindow.LegacyBackpackStyle[1] = {tid = 1157260, id = SystemData.Settings.LegacyBackpackStyle.LEGACY_BACKPACK_DEFAULT}
SettingsWindow.LegacyBackpackStyle[2] = {tid = 1157261, id = SystemData.Settings.LegacyBackpackStyle.LEGACY_BACKPACK_SUEDE} --Suede
SettingsWindow.LegacyBackpackStyle[3] = {tid = 1157262, id = SystemData.Settings.LegacyBackpackStyle.LEGACY_BACKPACK_POLAR_BEAR} -- Polar Bear
SettingsWindow.LegacyBackpackStyle[4] = {tid = 1157263, id = SystemData.Settings.LegacyBackpackStyle.LEGACY_BACKPACK_GHOUL_SKIN} --Ghoul Skin
SettingsWindow.NUM_LEGACYBACKPACKSTYLES = 4

SettingsWindow.FontSizes = {}
SettingsWindow.FontSizes[1] = 12
SettingsWindow.FontSizes[2] = 14
SettingsWindow.FontSizes[3] = 16
SettingsWindow.FontSizes[4] = 18
SettingsWindow.FontSizes[5] = 20
SettingsWindow.FontSizes[6] = 22
SettingsWindow.FontSizes[7] = 24
SettingsWindow.NUM_FONT_SIZES = 7

SettingsWindow.ChatFadeTime = {}
SettingsWindow.ChatFadeTime[1] = 1
SettingsWindow.ChatFadeTime[2] = 2
SettingsWindow.ChatFadeTime[3] = 3
SettingsWindow.ChatFadeTime[4] = 4
SettingsWindow.ChatFadeTime[5] = 5
SettingsWindow.NUM_FADE_TIMES = 5

SettingsWindow.Languages = {}
SettingsWindow.Languages[1] = {tid = 1077459, id = SystemData.Settings.Language.LANGUAGE_ENU}
SettingsWindow.Languages[2] = {tid = 1077460, id = SystemData.Settings.Language.LANGUAGE_JPN}
SettingsWindow.Languages[3] = {tid = 1078516, id = SystemData.Settings.Language.LANGUAGE_CHINESE_TRADITIONAL}
SettingsWindow.Languages[4] = {tid = 1156035, id = SystemData.Settings.Language.LANGUAGE_KOR}
SettingsWindow.NUM_LANGUAGES = 4

SettingsWindow.ShowNames = {}
SettingsWindow.ShowNames[1] = {tid = 1011051, id = SystemData.Settings.GameOptions.SHOWNAMES_NONE}
SettingsWindow.ShowNames[2] = {tid = 1078090, id = SystemData.Settings.GameOptions.SHOWNAMES_APPROACHING}
SettingsWindow.ShowNames[3] = {tid = 1078091, id = SystemData.Settings.GameOptions.SHOWNAMES_ALL}
SettingsWindow.NUM_SHOWNAMES = 3

SettingsWindow.ScrollWheelBehaviors = {}
SettingsWindow.ScrollWheelBehaviors[1] = {tid = 1079288, id = SystemData.Settings.GameOptions.MOUSESCROLL_ZOOM_IN_CAMERA }
SettingsWindow.ScrollWheelBehaviors[2] = {tid = 1079289, id = SystemData.Settings.GameOptions.MOUSESCROLL_ZOOM_OUT_CAMERA }
SettingsWindow.ScrollWheelBehaviors[3] = {tid = 1079177, id = SystemData.Settings.GameOptions.MOUSESCROLL_TARGET_NEXT_FRIENDLY }
SettingsWindow.ScrollWheelBehaviors[4] = {tid = 1111940, id = SystemData.Settings.GameOptions.MOUSESCROLL_TARGET_LAST_FRIENDLY }
SettingsWindow.ScrollWheelBehaviors[5] = {tid = 1079178, id = SystemData.Settings.GameOptions.MOUSESCROLL_TARGET_NEXT_ENEMY }
SettingsWindow.ScrollWheelBehaviors[6] = {tid = 1111941, id = SystemData.Settings.GameOptions.MOUSESCROLL_TARGET_LAST_ENEMY }
SettingsWindow.ScrollWheelBehaviors[7] = {tid = 1094824, id = SystemData.Settings.GameOptions.MOUSESCROLL_TARGET_NEXT_ANY }
SettingsWindow.ScrollWheelBehaviors[8] = {tid = 1111942, id = SystemData.Settings.GameOptions.MOUSESCROLL_TARGET_LAST_ANY }
SettingsWindow.ScrollWheelBehaviors[9] = {tid = 1079156, id = SystemData.Settings.GameOptions.MOUSESCROLL_CURSOR_TARGET_LAST }
SettingsWindow.ScrollWheelBehaviors[10] = {tid = 1079158, id = SystemData.Settings.GameOptions.MOUSESCROLL_CURSOR_TARGET_SELF }
SettingsWindow.ScrollWheelBehaviors[11] = {tid = 1079157, id = SystemData.Settings.GameOptions.MOUSESCROLL_CURSOR_TARGET_CURRENT }
SettingsWindow.ScrollWheelBehaviors[12] = {tid = 1112413, id = SystemData.Settings.GameOptions.MOUSESCROLL_CYCLE_CURSOR_TARGET }
SettingsWindow.ScrollWheelBehaviors[13] = {tid = 1115342, id = SystemData.Settings.GameOptions.MOUSESCROLL_CLEAR_TARGET_QUEUE }
SettingsWindow.ScrollWheelBehaviors[14] = {tid = 1011051, id = SystemData.Settings.GameOptions.MOUSESCROLL_NONE }
SettingsWindow.NUM_SCROLLWHEELBEHAVIORS = 14

SettingsWindow.ScrollWheelBehaviors_Legacy = {}
SettingsWindow.ScrollWheelBehaviors_Legacy[1] = {tid = 1079288, id = SystemData.Settings.GameOptions.MOUSESCROLL_ZOOM_IN_CAMERA }
SettingsWindow.ScrollWheelBehaviors_Legacy[2] = {tid = 1079289, id = SystemData.Settings.GameOptions.MOUSESCROLL_ZOOM_OUT_CAMERA }
SettingsWindow.ScrollWheelBehaviors_Legacy[3] = {tid = 1079156, id = SystemData.Settings.GameOptions.MOUSESCROLL_CURSOR_TARGET_LAST }
SettingsWindow.ScrollWheelBehaviors_Legacy[4] = {tid = 1079158, id = SystemData.Settings.GameOptions.MOUSESCROLL_CURSOR_TARGET_SELF }
SettingsWindow.ScrollWheelBehaviors_Legacy[5] = {tid = 1112413, id = SystemData.Settings.GameOptions.MOUSESCROLL_CYCLE_CURSOR_TARGET }
SettingsWindow.ScrollWheelBehaviors_Legacy[6] = {tid = 1115342, id = SystemData.Settings.GameOptions.MOUSESCROLL_CLEAR_TARGET_QUEUE }
SettingsWindow.ScrollWheelBehaviors_Legacy[7] = {tid = 1011051, id = SystemData.Settings.GameOptions.MOUSESCROLL_NONE }
SettingsWindow.NUM_SCROLLWHEELBEHAVIORS_LEGACY = 7

SettingsWindow.DelayValues = {}
SettingsWindow.DelayValues[1] = 1078334
SettingsWindow.DelayValues[2] = 1078336
SettingsWindow.DelayValues[3] = 1078337
SettingsWindow.DelayValues[4] = 1078338
SettingsWindow.DelayValues[5] = 1078339
SettingsWindow.DelayValues[6] = 1078340
SettingsWindow.NUM_DELAY_VALUES = 6

SettingsWindow.ContainerViewOptions = {}
SettingsWindow.ContainerViewOptions[1] = {name="List", tid=1079824}
SettingsWindow.ContainerViewOptions[2] = {name="Grid", tid=1079825}

SettingsWindow.ObjectHandles = {}
SettingsWindow.ObjectHandles[1] = { id = SystemData.Settings.ObjectHandleFilter.eDynamicFilter, tid = 1079457}
SettingsWindow.ObjectHandles[2] = { id = SystemData.Settings.ObjectHandleFilter.eCorpseFilter, tid = 1078368}
SettingsWindow.ObjectHandles[3] = { id = SystemData.Settings.ObjectHandleFilter.eNPCFilter, tid = 1079458}
SettingsWindow.ObjectHandles[4] = { id = SystemData.Settings.ObjectHandleFilter.eNPCVendorFilter, tid = 1079459}
SettingsWindow.ObjectHandles[5] = { id = SystemData.Settings.ObjectHandleFilter.eMobileFilter, tid = 1075672}
SettingsWindow.ObjectHandles[6] = { id = SystemData.Settings.ObjectHandleFilter.eItemsOnlyFilter, tid=1154804}
SettingsWindow.ObjectHandles[7] = { id = SystemData.Settings.ObjectHandleFilter.eLostItemsOnlyFilter, tid=1154805}

SettingsWindow.NUM_OBJHANDLE_FILTERS = #SettingsWindow.ObjectHandles

SettingsWindow.ObjectHandleSizes = {50, 100, 200, 300, -1}

-- NOTE_KEYBIND: Make sure the order of these match with the order of other keybinding symbol lists in code
SettingsWindow.Keybindings = {}
SettingsWindow.Keybindings[1] = { name = "MoveUp", tid = 1077791, type = "FORWARD" }
SettingsWindow.Keybindings[2] = { name = "MoveDown", tid = 1077792, type = "BACKWARD" }
SettingsWindow.Keybindings[3] = { name = "MoveLeft", tid = 1077793, type = "LEFT" }
SettingsWindow.Keybindings[4] = { name = "MoveRight", tid = 1077794, type = "RIGHT" }

SettingsWindow.Keybindings[5] = { name = "AttackMode", tid = 1077813, type = "MELEE_ATTACK" }
SettingsWindow.Keybindings[6] = { name = "PrimaryAttack", tid = 1079153, type = "USE_PRIMARY_ATTACK" }
SettingsWindow.Keybindings[7] = { name = "SecondaryAttack", tid = 1079154, type = "USE_SECONDARY_ATTACK" }

SettingsWindow.Keybindings[8] = { name = "NextGroupTarget", tid = 1079155, type = "NEXT_GROUP_TARGET" }
SettingsWindow.Keybindings[9] = { name = "NextEnemy", tid = 1077807, type = "NEXT_ENEMY_TARGET" }
SettingsWindow.Keybindings[10] = { name = "NextFriend", tid = 1077809, type = "NEXT_FRIENDLY_TARGET" }
SettingsWindow.Keybindings[11] = { name = "NextFollower", tid = 1112417, type = "NEXT_FOLLOWER_TARGET" }
SettingsWindow.Keybindings[12] = { name = "NextObject", tid = 1112424, type = "NEXT_OBJECT_TARGET" }
SettingsWindow.Keybindings[13] = { name = "NextTarget", tid = 1094822, type = "NEXT_TARGET" }

SettingsWindow.Keybindings[14] = { name = "PreviousGroupTarget", tid = 1112425, type = "PREVIOUS_GROUP_TARGET" }
SettingsWindow.Keybindings[15] = { name = "PreviousEnemy", tid = 1112426, type = "PREVIOUS_ENEMY_TARGET" }
SettingsWindow.Keybindings[16] = { name = "PreviousFriend", tid = 1112427, type = "PREVIOUS_FRIENDLY_TARGET" }
SettingsWindow.Keybindings[17] = { name = "PreviousFollower", tid = 1112428, type = "PREVIOUS_FOLLOWER_TARGET" }
SettingsWindow.Keybindings[18] = { name = "PreviousObject", tid = 1112429, type = "PREVIOUS_OBJECT_TARGET" }
SettingsWindow.Keybindings[19] = { name = "PreviousTarget", tid = 1112430, type = "PREVIOUS_TARGET" }

SettingsWindow.Keybindings[20] = { name = "NearestGroup", tid = 1112418, type = "NEAREST_GROUP_TARGET" }
SettingsWindow.Keybindings[21] = { name = "NearestEnemy", tid = 1077811, type = "NEAREST_ENEMY_TARGET" }
SettingsWindow.Keybindings[22] = { name = "NearestFriend", tid = 1077812, type = "NEAREST_FRIENDLY_TARGET" }
SettingsWindow.Keybindings[23] = { name = "NearestFollower", tid = 1112419, type = "NEAREST_FOLLOWER_TARGET" }
SettingsWindow.Keybindings[24] = { name = "NearestObject", tid = 1112423, type = "NEAREST_OBJECT_TARGET" }
SettingsWindow.Keybindings[25] = { name = "NearestTarget", tid = 1094823, type = "NEAREST_TARGET" }

SettingsWindow.Keybindings[26] = { name = "TargetSelf", tid = 1077801, type = "TARGET_SELF" }
SettingsWindow.Keybindings[27] = { name = "TargetG1", tid = 1077802, type = "TARGET_GROUP_MEMBER_1" }
SettingsWindow.Keybindings[28] = { name = "TargetG2", tid = 1077803, type = "TARGET_GROUP_MEMBER_2" }
SettingsWindow.Keybindings[29] = { name = "TargetG3", tid = 1077804, type = "TARGET_GROUP_MEMBER_3" }
SettingsWindow.Keybindings[30] = { name = "TargetG4", tid = 1077805, type = "TARGET_GROUP_MEMBER_4" }
SettingsWindow.Keybindings[31] = { name = "TargetG5", tid = 1077806, type = "TARGET_GROUP_MEMBER_5" }
SettingsWindow.Keybindings[32] = { name = "TargetG6", tid = 1079147, type = "TARGET_GROUP_MEMBER_6" }
SettingsWindow.Keybindings[33] = { name = "TargetG7", tid = 1079148, type = "TARGET_GROUP_MEMBER_7" }
SettingsWindow.Keybindings[34] = { name = "TargetG8", tid = 1079149, type = "TARGET_GROUP_MEMBER_8" }
SettingsWindow.Keybindings[35] = { name = "TargetG9", tid = 1079150, type = "TARGET_GROUP_MEMBER_9" }

SettingsWindow.Keybindings[36] = { name = "CursorTargetCurrent", tid = 1115345, type = "CURSOR_TARGET_CURRENT" }
SettingsWindow.Keybindings[37] = { name = "CursorTargetLast", tid = 1115346, type = "CURSOR_TARGET_LAST" }
SettingsWindow.Keybindings[38] = { name = "CursorTargetSelf", tid = 1115347, type = "CURSOR_TARGET_SELF" }
SettingsWindow.Keybindings[39] = { name = "CycleLastCursorTarget", tid = 1115348, type = "CYCLE_LAST_CURSOR_TARGET" }
SettingsWindow.Keybindings[40] = { name = "ClearTargetQueue", tid = 1115349, type = "CLEAR_TARGET_QUEUE" }

SettingsWindow.Keybindings[41] = { name = "CharacterWin", tid = 1077795, type = "PAPERDOLL_CHARACTER_WINDOW" }
SettingsWindow.Keybindings[42] = { name = "BackpackWin", tid = 1077796, type = "BACKPACK_WINDOW" }
SettingsWindow.Keybindings[43] = { name = "SkillsWin", tid = 1078992, type = "SKILLS_WINDOW" }
SettingsWindow.Keybindings[44] = { name = "ToggleMap", tid = 1078993, type = "WORLD_MAP_WINDOW" }
SettingsWindow.Keybindings[45] = { name = "QuestLogWin", tid = 1077799, type = "QUEST_LOG_WINDOW" }

SettingsWindow.Keybindings[46] = { name = "ToggleAlwaysRun", tid = 1113150, type = "TOGGLE_ALWAYS_RUN" }

SettingsWindow.Keybindings[47] = { name = "ZoomIn", tid = 1079288, type = "ZOOM_IN" }
SettingsWindow.Keybindings[48] = { name = "ZoomOut", tid = 1079289, type = "ZOOM_OUT" }
SettingsWindow.Keybindings[49] = { name = "ZoomReset", tid = 1079290, type = "ZOOM_RESET" }

SettingsWindow.Keybindings[50] = { name = "Screenshot", tid = 1079819, type = "SCREENSHOT" }
SettingsWindow.Keybindings[51] = { name = "ToggleInterface", tid = 1079817, type = "TOGGLE_UI" }
SettingsWindow.Keybindings[52] = { name = "ReloadInterface", tid = 1079820, type = "RELOAD_UI" }
SettingsWindow.Keybindings[53] = { name = "ToggleCoT", tid = 1079818, type = "TOGGLE_CIRCLE_OF_TRANSPARENCY" }
SettingsWindow.Keybindings[54] = { name = "CycleChatForward", tid = 1115574, type = "CYCLE_CHAT_FORWARD" }
SettingsWindow.Keybindings[55] = { name = "CycleChatBackward", tid = 1115575, type = "CYCLE_CHAT_BACKWARD" }

SettingsWindow.Keybindings[56] = { name = "QuitGame", tid = 1114308, type = "QUIT_GAME" }
SettingsWindow.Keybindings[57] = { name = "LogOut", tid = 1115334, type = "LOG_OUT" }

SettingsWindow.NON_LEGACY_BINDING_MIN = 8
SettingsWindow.NON_LEGACY_BINDING_MAX = 36

SettingsWindow.TID = {UserSetting = 1077814, Graphics = 1077815, KeyBindings = 1077816, Options = 1015326, Resolution = 1077817, 
					 WindowRes = 1077818, MaxFramerate = 1112340, FullRes = 1077819, ShowFrame = 1077820, UseFull = 1077821, EnableSound = 1077823, SoundVol = 1094691, 
					 Language = 1077824, Okay = 3000093, Apply = 3000090, Reset = 1077825, Cancel = 1006045, Quarter = 1078023, Full = 1074240, 
					 Sound = 3000390, Interface = 3000395, PlayFootsteps = 1078077, CircleOfTransparency = 1078079, 
					 AlwaysRun = 1078078, Movie = 3000190, ObjectHandles = 1062947, ObjectHandleFilter = 1079461, ObjectHandleQuantity = 1094696,
					 QueryBeforeCriminalActions = 1078080, HoldShiftToUnstack = 1112076, FilterObscenity = 3000460, OverheadChatFadeDelay = 1078084, 
					 OverheadChat = 1078083, Tooltips = 1115211, TooltipDelay = 1078086, PlayerNameColors = 1078087, ShowNames = 1078093, Filter = 3000173, IgnorePlayers = 3000462, IgnoreConfPlayers = 1151906,
					 MusicVolume = 1078578, EnableMusic = 1078577, Animation = 1079368, EffectsVolume = 1078576, EnableEffects = 1078575, AlwaysAttack = 1078858, ShowStrLabel = 1079171,
					 LegacyChat = 1079172, PlayIdleAnimation = 1094692, GameOptions = 1094695, System = 1078905, Chat = 3000131, Legacy = 1094697, BackpackStyle=1157257, 
					 UiScale = 1079205, GenericGumpScale = 1158011, Gamma = 3000166, ParticleLOD = 1079213, ParticleFilter = 1112330, Input = 1094693, Mouse = 1094694, NotAvailable = 1094717,
					 ShowShadows = 1079286, EnableVsync = 1112689, ShowChatWindow = 1079299, Bindings = 1079337, UseLegacyContainers = 1094708, ShowFoliage = 1079814, 
                     LegacyTargeting = 1094710, ScrollWheelUp = 1111944, ScrollWheelDown = 1111945, DefaultContainerView = 1079827, DefaultCorpseView = 1079828, TipoftheDay = 1094689,
                     Display = 3000396, Environment = 1077415, DiskCache = 1079480, LegacyKeyDefault = 1079163, MMOKeyDefault = 1111866, CustomUI = 1079523, EnableAutorun = 1115321,
					 EnablePathfinding = 1115324, TargetQueueing = 1115337, ShiftRightClickContextMenus = 1115355, PartyInvitePopUp = 1115367, EnglishNames = 1115913,
					 IgnoreMouseActionsOnSelf = 1115918, ShowCorpseNames = 1115927, HardwareDeathEffect = 1115993, EnableChatLog = 1149998, UseLegacyPaperdolls = 1150185, ResetUILocPos = 1153107, Atlas = 1155405,
					 PlayFlyingAnimation = 1158627,	DisplayAllHouseContents = 1159003,			 
					 
					 Healthbars = 1155313, CenterScreenText = 1155428, Containers = 1155277, Buttons = 1155323, Colors = 1155351, SpellButtons = 1155332, OverheadText = 1155333,
					 
					 ToggleMapCombo = 1155294, ToggleWindowSnap = 1155296, BlockWarOnPets = 1155300, BlockWarOnParty = 1155302, BlockWarOnGuild = 1155304, LowHPLabel = 1155306, LowHPPetLabel = 1155307, 
					 IgnoreSummons = 1155311, BlockOthersPaperdoll = 1155298, ToggleWarShield = 1155367, AutoIgnoreCorpses=1156263,
					 
					 ToggleGridLegacy = 1155280, ToggleGrid = 1155282, ToggleContentsInfo = 1155284, ToggleAlternateGrid = 1155286, ToggleExtraBright = 1155288, ContainerGridColor = 1155290, ContainerGridAlternateColor = 1155292,
					
					 StatusWindowStyleLabel = 1155314, HealthbarsButtons = 1155317, ToggleNotorietyAura = 1155319, ToggleMobileArrow = 1155321, LegacyCloseStyle = 1155324, PetLegacyCloseStyle = 1155326, ShowCloseExtract = 1155328,
					 HealthBarWod = 1155330, DisableSpells = 1155334, ShowSpellName = 1155336, noPoisonOthers = 1155338, DefaulTextSizePlus = 1155341, DefaulTextSizeMinus = 1155342, clickableNames = 1155340, OverheadChatFont = 1155343,
					 OverheadNamesFont = 1155344, OverheadSpellFont = 1155345, OverheadDamageFont = 1155346,  DefaulHealTextColor = 1155352, DefaulCurseTextColor = 1155353, DefaulParaTextColor = 1155354,  DefaulNeutralTextColor = 1155355,
					 DefaulNegTextColor = 1155356, DefaulPosTextColor = 1155357, DefaulYouTextColor = 1155358, DefaulPetTextColor = 1155359, DefaulEnemyTextColor = 1155360, DefaultPhysicalTextColor = 1155361, DefaultFireTextColor = 1155362, 
					 DefaultColdTextColor = 1155363, DefaultPoisonTextColor = 1155364, DefaultEnergyTextColor = 1155365, DefaulChaosTextColor = 1155366,
					 }
					 
SettingsWindow.DetailTID = {	UseFull = 1115267, FullRes = 1115269, MaxFramerate = 1115270, ShowFrame = 1115271,
								Gamma = 1115272, ShowFoliage = 1115275, ShowShadows = 1115276, EnableVsync = 1115277,
								CircleOfTransparency = 1115278, ParticleLOD = 1115279, ParticleFilter = 1115280,
								PlayIdleAnimation = 1115281, Animation = 1115282, ScrollWheelUp = 1115283,
								ScrollWheelDown = 1115284, LegacyKeyDefault = 1115285, MMOKeyDefault = 1115286,
								EnableSound = 1115287, SoundVol = 1115288, EnableEffects = 1115289, EffectsVolume = 1115290,
								EnableMusic = 1115291, MusicVolume = 1115292, PlayFootsteps = 1115293, Language = 1115294,
								DiskCache = 1115295, AlwaysRun = 1115296, AlwaysAttack = 1115297,
								QueryBeforeCriminalActions = 1115298, HoldShiftToUnstack = 1115299, CustomUI = 1115300,
								UiScale = 1115301, GenericGumpScale=1158012, DefaultContainerView = 1115302, DefaultCorpseView = 1115303,
								ShowStrLabel = 1115304, Tooltips = 1115305, TipoftheDay = 1115306,
								ObjectHandleFilter = 1115307, ObjectHandleQuantity = 1115308, ShowNames = 1115309, BackpackStyle=1157266,
								OverheadChat = 1115310, OverheadChatFadeDelay = 1115311, LegacyChat = 1115312,
								UseLegacyContainers = 1115313, LegacyTargeting = 1115314, FilterObscenity = 1115315,
								IgnorePlayers = 1115316, IgnoreConfPlayers = 1151906, EnableAutorun = 1115322, EnablePathfinding = 1115325,
								TargetQueueing = 1115338, ShiftRightClickContextMenus = 1115356, PartyInvitePopUp = 1115368,
                                EnglishNames = 1115914, IgnoreMouseActionsOnSelf = 1115919, ShowCorpseNames = 1115928, 
                                HardwareDeathEffect = 1115994, EnableChatLog = 1149999, UseLegacyPaperdolls = 1150186,
                               	PlayFlyingAnimation = 1158628, DisplayAllHouseContents = 1159138,
					 
								ToggleMapCombo = 1155295, ToggleWindowSnap = 1155297, BlockWarOnPets = 1155301, BlockWarOnParty = 1155303, BlockWarOnGuild = 1155305, LowHPLabel = 1155309, LowHPPetLabel = 1155310, 
								IgnoreSummons = 1155312, BlockOthersPaperdoll = 1155299, ToggleWarShield = 1155368, AutoIgnoreCorpses=1156264,
								 
								ToggleGridLegacy = 1155281, ToggleGrid = 1155283, ToggleContentsInfo = 1155285, ToggleAlternateGrid = 1155287, ToggleExtraBright = 1155289, ContainerGridColor = 1155291, ContainerGridAlternateColor = 1155293,
								 
								HealthbarsButtons = 1155318, ToggleNotorietyAura = 1155320, ToggleMobileArrow = 1155322, LegacyCloseStyle = 1155325, PetLegacyCloseStyle = 1155327, ShowCloseExtract = 1155329,
								HealthBarWod = 1155331, DisableSpells = 1155335, ShowSpellName = 1155337, noPoisonOthers = 1155339,
							}

SettingsWindow.TID_BINDING_CONFLICT_TITLE = 1079169
SettingsWindow.TID_BINDING_CONFLICT_BODY = 1079170
SettingsWindow.TID_BINDING_CONFLICT_QUESTION = 1094839
SettingsWindow.TID_YES = 1049717
SettingsWindow.TID_NO = 1049718
SettingsWindow.TID_INFO = 1011233
SettingsWindow.TID_RESETLEGACYBINDINGS_CHAT = 1079400
SettingsWindow.TID_RESETDEFAULTBINDINGS = 1094698
SettingsWindow.TID_RESETCHATSETTINGS = 1094699

SettingsWindow.TID_FRAMERATE = { 1112341, 1112342, 1112343, 1112344, 1112345 }

SettingsWindow.TID_DETAILS = { 1079210, 1079211, 1079212 }
SettingsWindow.TID_FILTERS = {1112331, 1112332, 1112333, 1112334, 1158020}

SettingsWindow.TID_ANIMATION = {1079210, 1079211, 1079212}

SettingsWindow.RecordingKey = false

SettingsWindow.PreviousBadWordCount = 0
SettingsWindow.PreviousIgnoreListCount = 0
SettingsWindow.CurIgnoreListIdx = -1
SettingsWindow.PreviousIgnoreConfListCount = 0
SettingsWindow.CurIgnoreConfListIdx = -1

--SettingsWindow.ENABLE_CUSTOM_SKINS = false -- enable this element? search for this tag to find all uses of this element also!
--SettingsWindow.TID_CUSTOM_SKINS_TEXT = 1011012 -- "Cancel"( placeholder )-- Label on the right of the combo box
--SettingsWindow.CustomSkins = {} -- table containing data for the different skins, may need to be initalized before use
--SettingsWindow.CustomSkins[1] = { tid = 3006115, id = 1 } -- "Resign( placeholder )-- Fist listed element in combo box
--SettingsWindow.CustomSkins[2] = { tid = 1078056, id = 2 } -- "MORE"( placeholder )
--SettingsWindow.CustomSkins[3] = { tid = 1011011, id = 3 } -- "CONTINUE"( placeholder )-- Last listed element in combo box

----------------------------------------------------------------
-- LoginWindow Functions
----------------------------------------------------------------

-- OnInitialize Handler()
function SettingsWindow.Initialize()

	Interface.OnCloseCallBack["SettingsWindow"] = SettingsWindow.OnCancelButton
	
	WindowRegisterEventHandler( "Root", SystemData.Events.PROFANITYLIST_UPDATED, "SettingsWindow.ProfanityListUpdated" )
	
	WindowUtils.SetWindowTitle( "SettingsWindow", GetStringFromTid( SettingsWindow.TID.UserSetting ) )

	-- Tab Buttons
	ButtonSetText( "SettingsWindowGraphicsTabButton", GetStringFromTid( SettingsWindow.TID.Graphics ) )
	ButtonSetText( "SettingsWindowKeyBindingsTabButton", GetStringFromTid( SettingsWindow.TID.Input ) )
	ButtonSetText( "SettingsWindowOptionsTabButton", GetStringFromTid( SettingsWindow.TID.Options ) )
	ButtonSetText( "SettingsWindowSoundTabButton", GetStringFromTid( SettingsWindow.TID.Sound ) )
	ButtonSetText( "SettingsWindowLegacyTabButton", GetStringFromTid( SettingsWindow.TID.Legacy ) )
	ButtonSetText( "SettingsWindowProfanityTabButton", GetStringFromTid( SettingsWindow.TID.Filter ) )
	ButtonSetText( "SettingsWindowMobilesOnScreenTabButton", GetStringFromTid(1154852) )	
	ButtonSetText( "SettingsWindowHealthbarsTabButton", GetStringFromTid(1155276) )
	ButtonSetText( "SettingsWindowContainersTabButton", GetStringFromTid(1155277) )
	ButtonSetText( "SettingsWindowOverheadTextTabButton", GetStringFromTid(1155278) )
	
	-- SubSection Labels
	LabelSetText( "SettingsGraphicsDisplaySubSectionLabel", GetStringFromTid( SettingsWindow.TID.Display ) )
	LabelSetText( "SettingsGraphicsEnvironmentSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Environment ) )
	LabelSetText( "SettingsKeyBindingsMouseSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Mouse ) )
	LabelSetText( "SettingsKeyBindingsKeyboardSubSectionLabel", GetStringFromTid( SettingsWindow.TID.KeyBindings ) )
	LabelSetText( "SettingsSoundSoundSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Sound ) )
	LabelSetText( "SettingsOptionsMapOptionsSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Atlas ) )
	LabelSetText( "SettingsOptionsGameOptionsSubSectionLabel", GetStringFromTid( SettingsWindow.TID.GameOptions ) )
	LabelSetText( "SettingsOptionsCenterScreenTextSubSectionLabel", GetStringFromTid( SettingsWindow.TID.CenterScreenText ) )
	LabelSetText( "SettingsOptionsInterfaceSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Interface ) )
	LabelSetText( "SettingsOptionsSystemSubSectionLabel", GetStringFromTid( SettingsWindow.TID.System ) )
	--LabelSetText( "SettingsOptionsChatSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Chat ) )
	LabelSetText( "SettingsLegacyLegacySubSectionLabel", GetStringFromTid( SettingsWindow.TID.Legacy ) )
	LabelSetText( "SettingsBadWordFilterFilterSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Filter ) )
	
	
	LabelSetText( "ContainersOptionsSystemSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Containers ) )
	LabelSetText( "HealthbarsOptionsStatusWindowSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Healthbars ) )
	LabelSetText( "HealthbarsOptionsButtonsSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Buttons ) )
	LabelSetText( "HealthbarsOptionsSpellsButtonsSubSectionLabel", GetStringFromTid( SettingsWindow.TID.SpellButtons ) )
	LabelSetText( "OverheadTextOptionsOTSubSectionLabel", GetStringFromTid( SettingsWindow.TID.OverheadText ) )
	LabelSetText( "OverheadTextOptionsColorsSubSectionLabel", GetStringFromTid( SettingsWindow.TID.Colors ) )
	
	-- Buttons
	ButtonSetText( "SettingsWindowOkayButton", GetStringFromTid( SettingsWindow.TID.Okay ) )
	ButtonSetText( "SettingsWindowApplyButton", GetStringFromTid( SettingsWindow.TID.Apply ) )
	ButtonSetText( "SettingsWindowResetButton", GetStringFromTid( SettingsWindow.TID.Reset ) )
	ButtonSetText( "SettingsWindowCancelButton", GetStringFromTid( SettingsWindow.TID.Cancel ) )
	
	--[[ this no longer seems to be necessary
	ButtonSetStayDownFlag( "SettingsWindowGraphicsTabButton", true )
	ButtonSetStayDownFlag( "SettingsWindowKeyBindingsTabButton", true )
	ButtonSetStayDownFlag( "SettingsWindowOptionsTabButton", true )
	--]]
	
	-- Start with graphics window open
	SettingsWindow.OpenGraphicsTab()
	
	-- Graphics --
	
	-- Use Fullscreen
	LabelSetText( "SettingsGraphicsUseFullscreenLabel", GetStringFromTid( SettingsWindow.TID.UseFull ) )
	WindowSetId( "SettingsGraphicsUseFullscreenLabel", SettingsWindow.DetailTID.UseFull )
	ButtonSetCheckButtonFlag( "SettingsGraphicsUseFullscreenButton", true )
	
	-- Fullscreen Resolution
	LabelSetText( "SettingsGraphicsFullScreenResLabel", GetStringFromTid( SettingsWindow.TID.FullRes ) )
	WindowSetId( "SettingsGraphicsFullScreenResLabel", SettingsWindow.DetailTID.FullRes )
	for res = 1, table.getn( SystemData.AvailableResolutions.widths )do
		ComboBoxAddMenuItem( "SettingsGraphicsFullScreenResCombo", L""..SystemData.AvailableResolutions.widths[res]..L" x "..SystemData.AvailableResolutions.heights[res] )
	end
	
	-- Framerate Max
	LabelSetText( "SettingsGraphicsFramerateMaxLabel", GetStringFromTid( SettingsWindow.TID.MaxFramerate ) )
	WindowSetId( "SettingsGraphicsFramerateMaxLabel", SettingsWindow.DetailTID.MaxFramerate )
	for index, tid in ipairs( SettingsWindow.TID_FRAMERATE )do
		ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", GetStringFromTid( tid ) )
	end
	
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"70 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"80 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"90 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"100 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"110 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"120 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"130 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"140 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"150 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"160 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"170 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"180 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"190 FPS" )
	ComboBoxAddMenuItem( "SettingsGraphicsFramerateMaxCombo", L"200 FPS" )
	
	-- Show Frame
	LabelSetText( "SettingsGraphicsShowFrameLabel", GetStringFromTid( SettingsWindow.TID.ShowFrame ) )
	WindowSetId( "SettingsGraphicsShowFrameLabel", SettingsWindow.DetailTID.ShowFrame )
	ButtonSetCheckButtonFlag( "SettingsGraphicsShowFrameButton", true )
	
	-- Brightness
	LabelSetText( "GammaText", GetStringFromTid( SettingsWindow.TID.Gamma ) )
	WindowSetId( "GammaText", SettingsWindow.DetailTID.Gamma )
	
	-- Show Foliage
	LabelSetText( "SettingsGraphicsShowFoliageLabel", GetStringFromTid( SettingsWindow.TID.ShowFoliage ) )
	WindowSetId( "SettingsGraphicsShowFoliageLabel", SettingsWindow.DetailTID.ShowFoliage )
	ButtonSetStayDownFlag( "SettingsGraphicsShowFoliageButton", true )
	ButtonSetCheckButtonFlag( "SettingsGraphicsShowFoliageButton", true )
	
	-- Show Shadows
	LabelSetText( "SettingsGraphicsShowShadowsLabel", GetStringFromTid( SettingsWindow.TID.ShowShadows ) )
	WindowSetId( "SettingsGraphicsShowShadowsLabel", SettingsWindow.DetailTID.ShowShadows )
	ButtonSetCheckButtonFlag( "SettingsGraphicsShowShadowsButton", true )

	-- Enable Vsync
	LabelSetText( "SettingsGraphicsEnableVSyncLabel", GetStringFromTid( SettingsWindow.TID.EnableVsync ) )
	WindowSetId( "SettingsGraphicsEnableVSyncLabel", SettingsWindow.DetailTID.EnableVsync )
	ButtonSetCheckButtonFlag( "SettingsGraphicsEnableVSyncButton", true )
	
	-- Use Circle of Transparency
	LabelSetText( "SettingsGraphicsCircleOfTransparencyLabel", GetStringFromTid( SettingsWindow.TID.CircleOfTransparency ) )
	WindowSetId( "SettingsGraphicsCircleOfTransparencyLabel", SettingsWindow.DetailTID.CircleOfTransparency )
	ButtonSetCheckButtonFlag( "SettingsGraphicsCircleOfTransparencyButton", true )
    
    -- Use Old Death Effect
	LabelSetText( "SettingsGraphicsHardwareDeathEffectLabel", GetStringFromTid( SettingsWindow.TID.HardwareDeathEffect ) )
	WindowSetId( "SettingsGraphicsHardwareDeathEffectLabel", SettingsWindow.DetailTID.HardwareDeathEffect )
	ButtonSetCheckButtonFlag( "SettingsGraphicsHardwareDeathEffectButton", true )
	
	-- Particle Detail
	LabelSetText( "SettingsGraphicsParticleLODLabel", GetStringFromTid( SettingsWindow.TID.ParticleLOD )..L":" )
	WindowSetId( "SettingsGraphicsParticleLODLabel", SettingsWindow.DetailTID.ParticleLOD )
	for index, tid in ipairs( SettingsWindow.TID_DETAILS )do
		ComboBoxAddMenuItem( "SettingsGraphicsParticleLODCombo", GetStringFromTid( tid ) )
	end
	
	-- Particle Filter
	LabelSetText( "SettingsGraphicsParticleFilterLabel", GetStringFromTid( SettingsWindow.TID.ParticleFilter )..L":" )
	WindowSetId( "SettingsGraphicsParticleFilterLabel", SettingsWindow.DetailTID.ParticleFilter )
	for index, tid in ipairs( SettingsWindow.TID_FILTERS )do
		ComboBoxAddMenuItem( "SettingsGraphicsParticleFilterCombo", GetStringFromTid( tid ) )
	end

	-- Idle Animation (Restart Required)
	LabelSetText( "SettingsGraphicsPlayIdleAnimationLabel", GetStringFromTid( SettingsWindow.TID.PlayIdleAnimation ) )
	WindowSetId( "SettingsGraphicsPlayIdleAnimationLabel", SettingsWindow.DetailTID.PlayIdleAnimation )
	ButtonSetCheckButtonFlag( "SettingsGraphicsPlayIdleAnimationButton", true )
	
	-- Animation (Restart Required)
	LabelSetText( "SettingsGraphicsAnimationLabel", GetStringFromTid( SettingsWindow.TID.Animation )..L":" )
	WindowSetId( "SettingsGraphicsAnimationLabel", SettingsWindow.DetailTID.Animation )
	for index, tid in ipairs( SettingsWindow.TID_ANIMATION )do
		ComboBoxAddMenuItem( "SettingsGraphicsAnimationCombo", GetStringFromTid( tid ) )
	end

	-- Idle Animation (Restart Required)
	LabelSetText( "SettingsGraphicsPlayFlyingAnimationLabel", GetStringFromTid( SettingsWindow.TID.PlayFlyingAnimation ) )
	WindowSetId( "SettingsGraphicsPlayFlyingAnimationLabel", SettingsWindow.DetailTID.PlayFlyingAnimation )
	ButtonSetCheckButtonFlag( "SettingsGraphicsPlayFlyingAnimationButton", true )

	-- Display All House Contents
	LabelSetText( "SettingsGraphicsDisplayAllHouseContentsLabel", GetStringFromTid( SettingsWindow.TID.DisplayAllHouseContents ) )
	WindowSetId( "SettingsGraphicsDisplayAllHouseContentsLabel", SettingsWindow.DetailTID.DisplayAllHouseContents )
	ButtonSetCheckButtonFlag( "SettingsGraphicsDisplayAllHouseContentsButton", true )


	-- Input --
	
	-- Scroll Wheel Behavior
	LabelSetText( "SettingsKeyBindingsScrollWheelUpLabel", GetStringFromTid( SettingsWindow.TID.ScrollWheelUp ) )
	WindowSetId( "SettingsKeyBindingsScrollWheelUpLabel", SettingsWindow.DetailTID.ScrollWheelUp )
	LabelSetText( "SettingsKeyBindingsScrollWheelDownLabel", GetStringFromTid( SettingsWindow.TID.ScrollWheelDown ) )
	WindowSetId( "SettingsKeyBindingsScrollWheelDownLabel", SettingsWindow.DetailTID.ScrollWheelDown )
	SettingsWindow.RefreshScrollWheelComboBoxes()
	
	-- Classic Key Default
	LabelSetText( "SettingsKeyDefaultWindowLegacyKeysName", GetStringFromTid( SettingsWindow.TID.LegacyKeyDefault ) )
	WindowSetId( "SettingsKeyDefaultWindowLegacyKeysName", SettingsWindow.DetailTID.LegacyKeyDefault )
	-- Enhanced Key Default
	LabelSetText( "SettingsKeyDefaultWindowMMOKeysName", GetStringFromTid( SettingsWindow.TID.MMOKeyDefault ) )
	WindowSetId( "SettingsKeyDefaultWindowMMOKeysName", SettingsWindow.DetailTID.MMOKeyDefault )
	
	-- Key Bindings
	for key = 1, table.getn( SettingsWindow.Keybindings )do
		LabelSetText( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name.."Action", GetStringFromTid( SettingsWindow.Keybindings[key].tid ) )
	end	

	-- Sound --
	
	-- Master Volume
	ButtonSetStayDownFlag( "MasterVolumeToggleButton", true )
	ButtonSetCheckButtonFlag( "MasterVolumeToggleButton", true )
		
	LabelSetText( "MasterVolumeText", GetStringFromTid( SettingsWindow.TID.SoundVol ) )
	WindowSetId( "MasterVolumeText", SettingsWindow.DetailTID.SoundVol )
	LabelSetText( "MasterVolumeToggleLabel", GetStringFromTid( SettingsWindow.TID.EnableSound ) )
	WindowSetId( "MasterVolumeToggleLabel", SettingsWindow.DetailTID.EnableSound )
	LabelSetText( "MasterVolumeVal", L""..( math.floor( SystemData.Settings.Sound.master.volume*100 ) ) )
	
	-- Effects Volume
	ButtonSetStayDownFlag( "EffectsVolumeToggleButton", true )
	ButtonSetCheckButtonFlag( "EffectsVolumeToggleButton", true )
	
	LabelSetText( "EffectsVolumeText", GetStringFromTid( SettingsWindow.TID.EffectsVolume ) )
	WindowSetId( "EffectsVolumeText", SettingsWindow.DetailTID.EffectsVolume )
	LabelSetText( "EffectsVolumeToggleLabel", GetStringFromTid( SettingsWindow.TID.EnableEffects ) )
	WindowSetId( "EffectsVolumeToggleLabel", SettingsWindow.DetailTID.EnableEffects )
	LabelSetText( "EffectsVolumeVal", L""..( math.floor( SystemData.Settings.Sound.effects.volume*100 ) ) )
	
	-- Music Volume
	ButtonSetStayDownFlag( "MusicVolumeToggleButton", true )
	ButtonSetCheckButtonFlag( "MusicVolumeToggleButton", true )
	
	LabelSetText( "MusicVolumeText", GetStringFromTid( SettingsWindow.TID.MusicVolume ) )
	WindowSetId( "MusicVolumeText", SettingsWindow.DetailTID.MusicVolume )
	LabelSetText( "MusicVolumeToggleLabel", GetStringFromTid( SettingsWindow.TID.EnableMusic ) )
	WindowSetId( "MusicVolumeToggleLabel", SettingsWindow.DetailTID.EnableMusic )
	LabelSetText( "MusicVolumeVal", L""..( math.floor( SystemData.Settings.Sound.music.volume*100 ) ) )

	-- Play Footsteps
	ButtonSetStayDownFlag( "PlayFootstepsToggleButton", true )
	ButtonSetCheckButtonFlag( "PlayFootstepsToggleButton", true )
	LabelSetText( "PlayFootstepsToggleLabel", GetStringFromTid( SettingsWindow.TID.PlayFootsteps ) )
	WindowSetId( "PlayFootstepsToggleLabel", SettingsWindow.DetailTID.PlayFootsteps )
	
	-- Options --
	
	-- Language
	LabelSetText( "SettingsOptionsLanguageLabel", GetStringFromTid( SettingsWindow.TID.Language ) )
	WindowSetId( "SettingsOptionsLanguageLabel", SettingsWindow.DetailTID.Language )
	for lan = 1, SettingsWindow.NUM_LANGUAGES do
		local text = GetStringFromTid( SettingsWindow.Languages[lan].tid )
		ComboBoxAddMenuItem( "SettingsOptionsLanguageCombo", L""..text )
	end
    
    -- English item names
    LabelSetText( "SettingsOptionsEnglishNamesLabel", GetStringFromTid( SettingsWindow.TID.EnglishNames ) ) 
    WindowSetId( "SettingsOptionsEnglishNamesLabel", SettingsWindow.DetailTID.EnglishNames )
    ButtonSetCheckButtonFlag( "SettingsOptionsEnglishNamesButton", true )
	
	-- Cache
	LabelSetText( "SettingsOptionsCacheSizeText", GetStringFromTid( SettingsWindow.TID.DiskCache ) )
	WindowSetId( "SettingsOptionsCacheSizeText", SettingsWindow.DetailTID.DiskCache )
	
	-- Map Combo
	LabelSetText( "ToggleMapCombo" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleMapCombo ) )
	WindowSetId( "ToggleMapCombo" .. "Label", SettingsWindow.DetailTID.ToggleMapCombo )
	ButtonSetCheckButtonFlag( "ToggleMapCombo" .. "Button", true )
	
	-- Toggle Cartographer
	--[[
	LabelSetText( "ToggleCartographer" .. "Label", L"Enable UO Mapper")-- GetStringFromTid( SettingsWindow.TID.ToggleCartographer ) )
	WindowSetId( "ToggleCartographer" .. "Label", SettingsWindow.DetailTID.ToggleCartographer )
	ButtonSetCheckButtonFlag( "ToggleCartographer" .. "Button", true )
	WindowSetShowing("ToggleCartographer", false)
	--]]
	
	-- Always Run
	LabelSetText( "AlwaysRunLabel", GetStringFromTid( SettingsWindow.TID.AlwaysRun ) )
	WindowSetId( "AlwaysRunLabel", SettingsWindow.DetailTID.AlwaysRun )
	ButtonSetCheckButtonFlag( "AlwaysRunButton", true )
	
	-- Enable Autorun
	LabelSetText( "EnableAutorunLabel", GetStringFromTid( SettingsWindow.TID.EnableAutorun ) )
	WindowSetId( "EnableAutorunLabel", SettingsWindow.DetailTID.EnableAutorun )
	ButtonSetCheckButtonFlag( "EnableAutorunButton", true )
	
	-- Enable Pathfinding
	LabelSetText( "EnablePathfindingLabel", GetStringFromTid( SettingsWindow.TID.EnablePathfinding ) )
	WindowSetId( "EnablePathfindingLabel", SettingsWindow.DetailTID.EnablePathfinding )
	ButtonSetCheckButtonFlag( "EnablePathfindingButton", true )
	
	-- Always Attack
	LabelSetText( "AlwaysAttackLabel", GetStringFromTid( SettingsWindow.TID.AlwaysAttack ) )
	WindowSetId( "AlwaysAttackLabel", SettingsWindow.DetailTID.AlwaysAttack )
	ButtonSetCheckButtonFlag( "AlwaysAttackButton", true )
	
	-- Query Before Criminal Actions
	LabelSetText( "QueryBeforeCriminalActionsLabel", GetStringFromTid( SettingsWindow.TID.QueryBeforeCriminalActions ) )
	WindowSetId( "QueryBeforeCriminalActionsLabel", SettingsWindow.DetailTID.QueryBeforeCriminalActions )
	ButtonSetCheckButtonFlag( "QueryBeforeCriminalActionsButton", true )
	
	-- Ignore Mouse Actions on Self
	LabelSetText( "IgnoreMouseActionsOnSelfLabel", GetStringFromTid( SettingsWindow.TID.IgnoreMouseActionsOnSelf ) )
	WindowSetId( "IgnoreMouseActionsOnSelfLabel", SettingsWindow.DetailTID.IgnoreMouseActionsOnSelf )
	ButtonSetCheckButtonFlag( "IgnoreMouseActionsOnSelfButton", true )
	
	-- Hold Shift to Unstack
	LabelSetText( "HoldShiftToUnstackLabel", GetStringFromTid( SettingsWindow.TID.HoldShiftToUnstack ) )
	WindowSetId( "HoldShiftToUnstackLabel", SettingsWindow.DetailTID.HoldShiftToUnstack )
	ButtonSetCheckButtonFlag( "HoldShiftToUnstackButton", true )
	
	-- Shift-Right Click to Open Context Menus
	LabelSetText( "ShiftRightClickContextMenusLabel", GetStringFromTid( SettingsWindow.TID.ShiftRightClickContextMenus ) )
	WindowSetId( "ShiftRightClickContextMenusLabel", SettingsWindow.DetailTID.ShiftRightClickContextMenus )
	ButtonSetCheckButtonFlag( "ShiftRightClickContextMenusButton", true )
	
	-- Cursor Target Queueing
	LabelSetText( "TargetQueueingLabel", GetStringFromTid( SettingsWindow.TID.TargetQueueing ) )
	WindowSetId( "TargetQueueingLabel", SettingsWindow.DetailTID.TargetQueueing )
	ButtonSetCheckButtonFlag( "TargetQueueingButton", true )
	
	-- Block Others Paperdoll
	LabelSetText( "BlockOthersPaperdoll" .. "Label", GetStringFromTid( SettingsWindow.TID.BlockOthersPaperdoll) )
	WindowSetId( "BlockOthersPaperdoll" .. "Label", SettingsWindow.DetailTID.BlockOthersPaperdoll )
	ButtonSetCheckButtonFlag( "BlockOthersPaperdoll" .. "Button", true )
		
	-- BlockWarOnPets
	LabelSetText( "BlockWarOnPets" .. "Label", GetStringFromTid( SettingsWindow.TID.BlockWarOnPets) )
	WindowSetId( "BlockWarOnPets" .. "Label", SettingsWindow.DetailTID.BlockWarOnPets )
	ButtonSetCheckButtonFlag( "BlockWarOnPets" .. "Button", true )
	
	-- BlockWarOnParty
	LabelSetText( "BlockWarOnParty" .. "Label", GetStringFromTid( SettingsWindow.TID.BlockWarOnParty) )
	WindowSetId( "BlockWarOnParty" .. "Label", SettingsWindow.DetailTID.BlockWarOnParty )
	ButtonSetCheckButtonFlag( "BlockWarOnParty" .. "Button", true )
	
	-- BlockWarOnGuild
	LabelSetText( "BlockWarOnGuild" .. "Label", GetStringFromTid( SettingsWindow.TID.BlockWarOnGuild) )
	WindowSetId( "BlockWarOnGuild" .. "Label", SettingsWindow.DetailTID.BlockWarOnGuild )
	ButtonSetCheckButtonFlag( "BlockWarOnGuild" .. "Button", true )
	
	-- ToggleWarShield
	LabelSetText( "ToggleWarShield" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleWarShield) )
	WindowSetId( "ToggleWarShield" .. "Label", SettingsWindow.DetailTID.ToggleWarShield )
	ButtonSetCheckButtonFlag( "ToggleWarShield" .. "Button", true )

	-- AutoIgnoreCorpses
	LabelSetText( "AutoIgnoreCorpses" .. "Label", GetStringFromTid( SettingsWindow.TID.AutoIgnoreCorpses) )
	WindowSetId( "AutoIgnoreCorpses" .. "Label", SettingsWindow.DetailTID.AutoIgnoreCorpses )
	ButtonSetCheckButtonFlag( "AutoIgnoreCorpses" .. "Button", true )

	-- LowHPLabel
	LabelSetText( "LowHP" .. "Label", GetStringFromTid( SettingsWindow.TID.LowHPLabel) )
	WindowSetId( "LowHP" .. "Label", SettingsWindow.DetailTID.LowHPLabel )
	
	ComboBoxAddMenuItem( "LowHPCombo", L"5%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"10%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"15%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"20%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"25%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"30%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"35%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"40%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"45%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"50%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"60%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"70%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"80%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"90%" )
	ComboBoxAddMenuItem( "LowHPCombo", L"99%" )
	ComboBoxAddMenuItem( "LowHPCombo", GetStringFromTid(1155308) )
	
	-- LowHPPetLabel
	LabelSetText( "LowHPPet" .. "Label", GetStringFromTid( SettingsWindow.TID.LowHPPetLabel) )
	WindowSetId( "LowHPPet" .. "Label", SettingsWindow.DetailTID.LowHPPetLabel )
	
	ComboBoxAddMenuItem( "LowHPPetCombo", L"5%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"10%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"15%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"20%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"25%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"30%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"35%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"40%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"45%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"50%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"60%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"70%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"80%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"90%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", L"99%" )
	ComboBoxAddMenuItem( "LowHPPetCombo", GetStringFromTid(1155308) )
	
	-- Ignore Summons
	LabelSetText( "IgnoreSummons" .. "Label", GetStringFromTid( SettingsWindow.TID.IgnoreSummons) )
	WindowSetId( "IgnoreSummons" .. "Label", SettingsWindow.DetailTID.IgnoreSummons )
	ButtonSetCheckButtonFlag( "IgnoreSummons" .. "Button", true )
	
	-- Use Custom UI
	LabelSetText( "CustomSkinsLabel", GetStringFromTid( SettingsWindow.TID.CustomUI )..L":" )
	WindowSetId( "CustomSkinsLabel", SettingsWindow.DetailTID.CustomUI )
	for skinItr = 1, #SystemData.CustomUIList do
		local text = SystemData.CustomUIList[skinItr]
		if text == "" then
			ComboBoxAddMenuItem( "CustomSkinsCombo", GetStringFromTid( 3000094 ) )-- "Default"
		else
			ComboBoxAddMenuItem( "CustomSkinsCombo", StringToWString( text ) )
		end
	end
	
	-- UI Scale
	LabelSetText( "UiScaleText", GetStringFromTid( SettingsWindow.TID.UiScale ) )
	WindowSetId( "UiScaleText", SettingsWindow.DetailTID.UiScale )

	-- Generic Gump Scale
	LabelSetText( "GenericGumpScaleText", GetStringFromTid( SettingsWindow.TID.GenericGumpScale ) )
	WindowSetId( "GenericGumpScaleText", SettingsWindow.DetailTID.GenericGumpScale )
	
	-- Show Corpse Names
	LabelSetText( "ShowCorpseNamesLabel", GetStringFromTid( SettingsWindow.TID.ShowCorpseNames ) )
	WindowSetId( "ShowCorpseNamesLabel", SettingsWindow.DetailTID.ShowCorpseNames )
	ButtonSetCheckButtonFlag( "ShowCorpseNamesButton", true )
	
	-- Always show Health, Mana, and Stamina
	LabelSetText( "ShowStrLabel", GetStringFromTid( SettingsWindow.TID.ShowStrLabel ) )
	WindowSetId( "ShowStrLabel", SettingsWindow.DetailTID.ShowStrLabel )
	ButtonSetCheckButtonFlag( "ShowStrButton", true )
	
	-- Tooltips
	LabelSetText( "TooltipsLabel", GetStringFromTid( SettingsWindow.TID.Tooltips ) )
	WindowSetId( "TooltipsLabel", SettingsWindow.DetailTID.Tooltips )
	ButtonSetCheckButtonFlag( "TooltipsButton", true )
	
	-- Display Pop-Up Window for Party Invitations
	LabelSetText( "PartyInvitePopUpLabel", GetStringFromTid( SettingsWindow.TID.PartyInvitePopUp ) )
	WindowSetId( "PartyInvitePopUpLabel", SettingsWindow.DetailTID.PartyInvitePopUp )
	ButtonSetCheckButtonFlag( "PartyInvitePopUpButton", true )
	
	-- Tip of the Day
	LabelSetText( "TipoftheDayLabel", GetStringFromTid( SettingsWindow.TID.TipoftheDay) )
	WindowSetId( "TipoftheDayLabel", SettingsWindow.DetailTID.TipoftheDay )
	ButtonSetCheckButtonFlag( "TipoftheDayButton", true )
	
	-- Toggle Window Snap
	LabelSetText( "ToggleWindowSnap" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleWindowSnap) )
	WindowSetId( "ToggleWindowSnap" .. "Label", SettingsWindow.DetailTID.ToggleWindowSnap )
	ButtonSetCheckButtonFlag( "ToggleWindowSnap" .. "Button", true )
	
	-- Reset UI Locs
	ButtonSetText( "ResetUILocButton", GetStringFromTid( SettingsWindow.TID.ResetUILocPos) )
	
	-- Object Handle Filter
	LabelSetText( "SettingsOptionsObjHandleFilterLabel", L""..GetStringFromTid( SettingsWindow.TID.ObjectHandleFilter )..L":" )
	WindowSetId( "SettingsOptionsObjHandleFilterLabel", SettingsWindow.DetailTID.ObjectHandleFilter )
	for filter = 1, SettingsWindow.NUM_OBJHANDLE_FILTERS do
		local text = L""
		if SettingsWindow.ObjectHandles[filter].tid then
			text = GetStringFromTid( SettingsWindow.ObjectHandles[filter].tid )
		elseif SettingsWindow.ObjectHandles[filter].text then
			text = SettingsWindow.ObjectHandles[filter].text
		end
		 
		ComboBoxAddMenuItem( "SettingsOptionsObjHandleFilterCombo", L""..text )
	end
	
	-- Object Handle Quantity
	LabelSetText( "SettingsOptionsObjHandleSizeLabel", L""..GetStringFromTid( SettingsWindow.TID.ObjectHandleQuantity )..L":" )
	WindowSetId( "SettingsOptionsObjHandleSizeLabel", SettingsWindow.DetailTID.ObjectHandleQuantity )
	for indexSize, objHandleSize in pairs( SettingsWindow.ObjectHandleSizes )do
		--( -1 )is considered max size
		local text = SettingsWindow.ObjectHandleSizes[indexSize]
		if( objHandleSize == -1 )then
			text = GetStringFromTid( 1077866 )-- "All"
		end
		ComboBoxAddMenuItem( "SettingsOptionsObjHandleSizeCombo", L""..text )
	end
	
	-- Show Names
	LabelSetText( "SettingsOptionsShowNamesLabel", GetStringFromTid( SettingsWindow.TID.ShowNames )..L":" )
	WindowSetId( "SettingsOptionsShowNamesLabel", SettingsWindow.DetailTID.ShowNames )
	for sn = 1, SettingsWindow.NUM_SHOWNAMES do
		local text = GetStringFromTid( SettingsWindow.ShowNames[sn].tid )
		ComboBoxAddMenuItem( "SettingsOptionsShowNamesCombo", L""..text )
	end
	
	-- Show Chat Windows
	--LabelSetText( "ShowChatWindowLabel", GetStringFromTid( SettingsWindow.TID.ShowChatWindow ) )
	--ButtonSetCheckButtonFlag( "ShowChatWindowButton", true )
		
	-- Overhead Chat
	LabelSetText( "OverheadChatLabel", GetStringFromTid( SettingsWindow.TID.OverheadChat ) )
	WindowSetId( "OverheadChatLabel", SettingsWindow.DetailTID.OverheadChat )
	ButtonSetCheckButtonFlag( "OverheadChatButton", true )
	
	-- Overhead Chat Fade Delay
	LabelSetText( "OverheadChatFadeDelayLabel", GetStringFromTid( SettingsWindow.TID.OverheadChatFadeDelay )..L":" )
	WindowSetId( "OverheadChatFadeDelayLabel", SettingsWindow.DetailTID.OverheadChatFadeDelay )
	for delay = 1, SettingsWindow.NUM_DELAY_VALUES do
		local text = GetStringFromTid( SettingsWindow.DelayValues[delay] )
		ComboBoxAddMenuItem( "OverheadChatFadeDelayCombo", L""..text )
	end
	
	-- Enable chat log
	LabelSetText( "EnableChatLogLabel", GetStringFromTid( SettingsWindow.TID.EnableChatLog ) )
	WindowSetId( "EnableChatLogLabel", SettingsWindow.DetailTID.EnableChatLog )
	ButtonSetCheckButtonFlag( "EnableChatLogButton", true )	
	
	-- Legacy --
		
	-- Legacy Chat
	LabelSetText( "LegacyChatLabel", GetStringFromTid( SettingsWindow.TID.LegacyChat ) )
	WindowSetId( "LegacyChatLabel", SettingsWindow.DetailTID.LegacyChat )
	ButtonSetCheckButtonFlag( "LegacyChatButton", true )
	
	-- Use Legacy Container Art
	LabelSetText( "SettingsLegacyUseLegacyContainersLabel", GetStringFromTid( SettingsWindow.TID.UseLegacyContainers ) )
	WindowSetId( "SettingsLegacyUseLegacyContainersLabel", SettingsWindow.DetailTID.UseLegacyContainers )
	ButtonSetCheckButtonFlag( "SettingsLegacyUseLegacyContainersButton", true )
	
	-- Use Legacy Paperdoll Art
	LabelSetText( "SettingsLegacyUseLegacyPaperdollsLabel", GetStringFromTid( SettingsWindow.TID.UseLegacyPaperdolls ) )
	WindowSetId( "SettingsLegacyUseLegacyPaperdollsLabel", SettingsWindow.DetailTID.UseLegacyPaperdolls )
	ButtonSetCheckButtonFlag( "SettingsLegacyUseLegacyPaperdollsButton", true )
	
	-- Use Legacy Targeting
	LabelSetText( "SettingsLegacyLegacyTargetingLabel", GetStringFromTid( SettingsWindow.TID.LegacyTargeting ) )
	WindowSetId( "SettingsLegacyLegacyTargetingLabel", SettingsWindow.DetailTID.LegacyTargeting )
	ButtonSetCheckButtonFlag( "SettingsLegacyLegacyTargetingButton", true )

	-- Backpack Style
	LabelSetText( "SettingsLegacyBackpackStyle", GetStringFromTid( SettingsWindow.TID.BackpackStyle )..L":" )
	WindowSetId( "SettingsLegacyBackpackStyle", SettingsWindow.DetailTID.BackpackStyle )
	for sn = 1, SettingsWindow.NUM_LEGACYBACKPACKSTYLES do
		local text = GetStringFromTid( SettingsWindow.LegacyBackpackStyle[sn].tid )
		ComboBoxAddMenuItem( "SettingsLegacyBackpackStyleCombo", L""..text )
	end
	
	-- Update the settings
	SettingsWindow.UpdateSettings()
			
	-- Update the scroll window
	ScrollWindowSetOffset( "SettingsGraphicsWindow", 0 )
	ScrollWindowUpdateScrollRect( "SettingsGraphicsWindow" )
	ScrollWindowSetOffset( "SettingsKeyBindingsWindow", 0 )
	ScrollWindowUpdateScrollRect( "SettingsKeyBindingsWindow" )
	ScrollWindowSetOffset( "SettingsSoundWindow", 0 )
	ScrollWindowUpdateScrollRect( "SettingsSoundWindow" )
	ScrollWindowSetOffset( "SettingsOptionsWindow", 0 )
	ScrollWindowUpdateScrollRect( "SettingsOptionsWindow" )
	ScrollWindowSetOffset( "SettingsLegacyWindow", 0 )
	ScrollWindowUpdateScrollRect( "SettingsLegacyWindow" )
	
	-- Call backs
	WindowRegisterEventHandler( "SettingsWindow", SystemData.Events.USER_SETTINGS_UPDATED, "SettingsWindow.UpdateSettings" )
	WindowRegisterEventHandler( "SettingsWindow", SystemData.Events.INTERFACE_KEY_RECORDED, "SettingsWindow.KeyRecorded" )
	WindowRegisterEventHandler( "SettingsWindow", SystemData.Events.INTERFACE_KEY_CANCEL_RECORD, "SettingsWindow.KeyCancelRecord" )
	WindowRegisterEventHandler( "SettingsWindow", SystemData.Events.TOGGLE_USER_PREFERENCE, "SettingsWindow.ToggleSettingsWindow" )
	
	-- Profanity --
	LabelSetText( "BadWordFilterOptionLabel", GetStringFromTid( SettingsWindow.TID.FilterObscenity ) )
	WindowSetId( "BadWordFilterOptionLabel", SettingsWindow.DetailTID.FilterObscenity )
	ButtonSetStayDownFlag( "BadWordFilterOptionButton", true )
	ButtonSetCheckButtonFlag( "BadWordFilterOptionButton", true )

	LabelSetText( "IgnoreListOptionLabel", GetStringFromTid( SettingsWindow.TID.IgnorePlayers ) )
	WindowSetId( "IgnoreListOptionLabel", SettingsWindow.DetailTID.IgnorePlayers )
	ButtonSetStayDownFlag( "IgnoreListOptionButton", true )
	ButtonSetCheckButtonFlag( "IgnoreListOptionButton", true )

	ButtonSetText( "IgnoreListAddButton", GetStringFromTid(1155473) )
	ButtonSetText( "IgnoreListChatListButton", GetStringFromTid(1155474) )
	ButtonSetText( "IgnoreListDeleteButton", GetStringFromTid(1155475) )
	
	LabelSetText( "IgnoreConfListOptionLabel", GetStringFromTid( SettingsWindow.TID.IgnoreConfPlayers ) )
	WindowSetId( "IgnoreConfListOptionLabel", SettingsWindow.DetailTID.IgnoreConfPlayers )
	ButtonSetStayDownFlag( "IgnoreConfListOptionButton", true )
	ButtonSetCheckButtonFlag( "IgnoreConfListOptionButton", true )
	
	ButtonSetText( "IgnoreConfListAddButton", GetStringFromTid(1155473) )
	ButtonSetText( "IgnoreConfListChatListButton", GetStringFromTid(1155474) )
	ButtonSetText( "IgnoreConfListDeleteButton", GetStringFromTid(1155475) )

	SettingsWindow.PopulateProfanityList()

	-- THESE ELEMENTS ARE NOT READY FOR THIS MILESTONE 3/23/2007. RESTORE THE FOLLOWING LINES AS THEY BECOME AVAILABLE!
	-- YOU WILL ALSO HAVE TO UNCOMMENT AND RE-ANCHOR THINGS IN THE XML!
	-- And you'll also need to restore the commented out LabelSetText functions for them
	-- WindowSetShowing( "Pathfinding", false )
	-- WindowSetShowing( "Movie", false )
	-- WindowSetShowing( "ObjectHandles", false )
	-- WindowSetShowing( "ChatWindowFadeDelaySliderBar", false )
	-- WindowSetShowing( "OverheadChatFadeDelaySliderBar", false )
	-- WindowSetShowing( "TooltipDelayLabel", false )
	-- WindowSetShowing( "TooltipDelayDelaySliderBar", false )
	
	-- CONTAINERS
	
	-- Default Container View
	-- Default Corpse View
	LabelSetText( "ContainerViewLabel", GetStringFromTid( SettingsWindow.TID.DefaultContainerView )..L":" )
	WindowSetId( "ContainerViewLabel", SettingsWindow.DetailTID.DefaultContainerView )
	LabelSetText( "CorpseViewLabel", GetStringFromTid( SettingsWindow.TID.DefaultCorpseView )..L":" )
	WindowSetId( "CorpseViewLabel", SettingsWindow.DetailTID.DefaultCorpseView )
	for id, data in ipairs(SettingsWindow.ContainerViewOptions) do
	    ComboBoxAddMenuItem( "ContainerViewCombo", GetStringFromTid(data.tid) )
	    ComboBoxAddMenuItem( "CorpseViewCombo", GetStringFromTid(data.tid) )
	end
	
	LabelSetText( "ToggleContentsInfo" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleContentsInfo ) )
	WindowSetId( "ToggleContentsInfo" .. "Label", SettingsWindow.DetailTID.ToggleContentsInfo )
	ButtonSetCheckButtonFlag( "ToggleContentsInfo" .. "Button", true )
	
	LabelSetText( "ToggleGridLegacy" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleGridLegacy ) )
	WindowSetId( "ToggleGridLegacy" .. "Label", SettingsWindow.DetailTID.ToggleGridLegacy )
	ButtonSetCheckButtonFlag( "ToggleGridLegacy" .. "Button", true )
	
	LabelSetText( "ToggleGrid" .. "Label",  GetStringFromTid( SettingsWindow.TID.ToggleGrid ) )
	WindowSetId( "ToggleGrid" .. "Label", SettingsWindow.DetailTID.ToggleGrid )
	ButtonSetCheckButtonFlag( "ToggleGrid" .. "Button", true )
	
	LabelSetText( "ToggleAlternateGrid" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleAlternateGrid ) )
	WindowSetId( "ToggleAlternateGrid" .. "Label", SettingsWindow.DetailTID.ToggleAlternateGrid )
	ButtonSetCheckButtonFlag( "ToggleAlternateGrid" .. "Button", true )
	
	LabelSetText( "ToggleExtraBright" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleExtraBright ) )
	WindowSetId( "ToggleExtraBright" .. "Label", SettingsWindow.DetailTID.ToggleExtraBright )
	ButtonSetCheckButtonFlag( "ToggleExtraBright" .. "Button", true )
	
	LabelSetText( "ContainerGridColor" .. "Label", GetStringFromTid( SettingsWindow.TID.ContainerGridColor ) )
	WindowSetId( "ContainerGridColor" .. "Label", SettingsWindow.DetailTID.ContainerGridColor )
	
	LabelSetText( "ContainerGridAlternateColor" .. "Label", GetStringFromTid( SettingsWindow.TID.ContainerGridAlternateColor ) )
	WindowSetId( "ContainerGridAlternateColor" .. "Label", SettingsWindow.DetailTID.ContainerGridAlternateColor )
	
	
	-- HEALTHBARS
	
	LabelSetText( "StatusWindowStyle" .. "Label", GetStringFromTid( SettingsWindow.TID.StatusWindowStyleLabel) )
	
	ComboBoxAddMenuItem( "StatusWindowStyleCombo", GetStringFromTid(1155315) )
	ComboBoxAddMenuItem( "StatusWindowStyleCombo", GetStringFromTid(1155316) )
	
	LabelSetText( "HealthbarsButtons" .. "Label", GetStringFromTid( SettingsWindow.TID.HealthbarsButtons ) )
	WindowSetId( "HealthbarsButtons" .. "Label", SettingsWindow.DetailTID.HealthbarsButtons )
	ButtonSetCheckButtonFlag( "HealthbarsButtons" .. "Button", true )
	
	LabelSetText( "ToggleNotorietyAura" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleNotorietyAura ) )
	WindowSetId( "ToggleNotorietyAura" .. "Label", SettingsWindow.DetailTID.ToggleNotorietyAura )
	ButtonSetCheckButtonFlag( "ToggleNotorietyAura" .. "Button", true )
	
	LabelSetText( "ToggleMobileArrow" .. "Label", GetStringFromTid( SettingsWindow.TID.ToggleMobileArrow ) )
	WindowSetId( "ToggleMobileArrow" .. "Label", SettingsWindow.DetailTID.ToggleMobileArrow )
	ButtonSetCheckButtonFlag( "ToggleMobileArrow" .. "Button", true )
	
	LabelSetText( "LegacyCloseStyle" .. "Label", GetStringFromTid( SettingsWindow.TID.LegacyCloseStyle ) )
	WindowSetId( "LegacyCloseStyle" .. "Label", SettingsWindow.DetailTID.LegacyCloseStyle )
	ButtonSetCheckButtonFlag( "LegacyCloseStyle" .. "Button", true )
	
	LabelSetText( "PetLegacyCloseStyle" .. "Label", GetStringFromTid( SettingsWindow.TID.PetLegacyCloseStyle ) )
	WindowSetId( "PetLegacyCloseStyle" .. "Label", SettingsWindow.DetailTID.PetLegacyCloseStyle )
	ButtonSetCheckButtonFlag( "PetLegacyCloseStyle" .. "Button", true )
	
	LabelSetText( "ShowCloseExtract" .. "Label", GetStringFromTid( SettingsWindow.TID.ShowCloseExtract ) )
	WindowSetId( "ShowCloseExtract" .. "Label", SettingsWindow.DetailTID.ShowCloseExtract )
	ButtonSetCheckButtonFlag( "ShowCloseExtract" .. "Button", true )
	
	LabelSetText( "HealthBarWod" .. "Label", GetStringFromTid( SettingsWindow.TID.HealthBarWod ) )
	WindowSetId( "HealthBarWod" .. "Label", SettingsWindow.DetailTID.HealthBarWod )
	ButtonSetCheckButtonFlag( "HealthBarWod" .. "Button", true )
	
	
	-- OVERHEAD TEXT
	
	LabelSetText( "clickableNames" .. "Label", GetStringFromTid( SettingsWindow.TID.clickableNames ) )
	ButtonSetCheckButtonFlag( "clickableNames" .. "Button", true )
	
	LabelSetText( "DisableSpells" .. "Label", GetStringFromTid( SettingsWindow.TID.DisableSpells ) )
	WindowSetId( "DisableSpells" .. "Label", SettingsWindow.DetailTID.DisableSpells )
	ButtonSetCheckButtonFlag( "DisableSpells" .. "Button", true )
	
	LabelSetText( "ShowSpellName" .. "Label", GetStringFromTid( SettingsWindow.TID.ShowSpellName ) )
	WindowSetId( "ShowSpellName" .. "Label", SettingsWindow.DetailTID.ShowSpellName )
	ButtonSetCheckButtonFlag( "ShowSpellName" .. "Button", true )
	
	LabelSetText( "noPoisonOthers" .. "Label", GetStringFromTid( SettingsWindow.TID.noPoisonOthers ) )
	WindowSetId( "noPoisonOthers" .. "Label", SettingsWindow.DetailTID.noPoisonOthers )
	ButtonSetCheckButtonFlag( "noPoisonOthers" .. "Button", true )
	
	ButtonSetText( "OverheadTextSizePlus",  GetStringFromTid( SettingsWindow.TID.DefaulTextSizePlus ) )
	
	ButtonSetText( "OverheadTextSizeMinus", GetStringFromTid( SettingsWindow.TID.DefaulTextSizeMinus ) )
	
	ButtonSetText( "OverheadChatFont",   GetStringFromTid( SettingsWindow.TID.OverheadChatFont ) )
	
	ButtonSetText( "OverheadNamesFont", GetStringFromTid( SettingsWindow.TID.OverheadNamesFont ) ) 
	
	ButtonSetText( "OverheadSpellFont", GetStringFromTid( SettingsWindow.TID.OverheadSpellFont ) ) 
	
	ButtonSetText( "OverheadDamageFont", GetStringFromTid( SettingsWindow.TID.OverheadDamageFont ) )
	
	LabelSetText( "OverheadTextOptionscolorHealLabel", GetStringFromTid( SettingsWindow.TID.DefaulHealTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorCurseLabel",  GetStringFromTid( SettingsWindow.TID.DefaulCurseTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorParaLabel", GetStringFromTid( SettingsWindow.TID.DefaulParaTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorNeutralLabel", GetStringFromTid( SettingsWindow.TID.DefaulNeutralTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorNegLabel", GetStringFromTid( SettingsWindow.TID.DefaulNegTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorPosLabel", GetStringFromTid( SettingsWindow.TID.DefaulPosTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorYouLabel", GetStringFromTid( SettingsWindow.TID.DefaulYouTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorPetLabel", GetStringFromTid( SettingsWindow.TID.DefaulPetTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorEnemyLabel", GetStringFromTid( SettingsWindow.TID.DefaulEnemyTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorPhysLabel", GetStringFromTid( SettingsWindow.TID.DefaultPhysicalTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorFireLabel", GetStringFromTid( SettingsWindow.TID.DefaultFireTextColor ) )
	
	LabelSetText( "OverheadTextOptionscolorColdLabel", GetStringFromTid( SettingsWindow.TID.DefaultColdTextColor ) ) 
	
	LabelSetText( "OverheadTextOptionscolorPoisLabel", GetStringFromTid( SettingsWindow.TID.DefaultPoisonTextColor ) ) 
	
	LabelSetText( "OverheadTextOptionscolorEnerLabel", GetStringFromTid( SettingsWindow.TID.DefaultEnergyTextColor ) ) 
	
	LabelSetText( "OverheadTextOptionscolorChaosLabel",GetStringFromTid( SettingsWindow.TID.DefaulChaosTextColor ) ) 
	
	
end

function SettingsWindow.ResetScrollWheelOptions()
	SettingsWindow.RefreshScrollWheelComboBoxes()
	
	ComboBoxSetSelectedMenuItem( "SettingsKeyBindingsScrollWheelUpCombo", 1 ) -- Default case
	ComboBoxSetSelectedMenuItem( "SettingsKeyBindingsScrollWheelDownCombo", 2 ) -- Default case
end

function SettingsWindow.RefreshScrollWheelComboBoxes()
	local scrollWheelBehaviors = SettingsWindow.ScrollWheelBehaviors
	local numScrollWheelBehaviors = SettingsWindow.NUM_SCROLLWHEELBEHAVIORS
	if ( ButtonGetPressedFlag( "SettingsLegacyLegacyTargetingButton" ) == true) then
		scrollWheelBehaviors = SettingsWindow.ScrollWheelBehaviors_Legacy
		numScrollWheelBehaviors = SettingsWindow.NUM_SCROLLWHEELBEHAVIORS_LEGACY
	end
	
	ComboBoxClearMenuItems( "SettingsKeyBindingsScrollWheelUpCombo" )
	for behavior = 1, numScrollWheelBehaviors do
		ComboBoxAddMenuItem( "SettingsKeyBindingsScrollWheelUpCombo", L""..GetStringFromTid( scrollWheelBehaviors[behavior].tid ) )
	end
		
	ComboBoxClearMenuItems( "SettingsKeyBindingsScrollWheelDownCombo" )
	for behavior = 1, numScrollWheelBehaviors do
		ComboBoxAddMenuItem( "SettingsKeyBindingsScrollWheelDownCombo", L""..GetStringFromTid( scrollWheelBehaviors[behavior].tid ) )
	end
end

function SettingsWindow.ToggleSettingsWindow()	
	ToggleWindowByName( "SettingsWindow", "", MainMenuWindow.ToggleSettingsWindow )	
end

function SettingsWindow.UpdateVolumeSliderSettings()
	--Debug.PrintToDebugConsole( L"SettingsWindow.UpdateSoundSettings()!" )
	local masterVolume = math.floor( 100 * SliderBarGetCurrentPosition( "MasterVolumeSliderBar" ) )
	local effectsVolume = math.floor( 100 * SliderBarGetCurrentPosition( "EffectsVolumeSliderBar" ) )
	local musicVolume = math.floor( 100 * SliderBarGetCurrentPosition( "MusicVolumeSliderBar" ) )

	LabelSetText( "MasterVolumeVal", L""..masterVolume )
	LabelSetText( "EffectsVolumeVal", L""..effectsVolume )
	LabelSetText( "MusicVolumeVal", L""..musicVolume )
end

function SettingsWindow.UpdateSliderSettings(curPos)
	-- update ui scale
	
	
	local barName = string.gsub(SystemData.ActiveWindow.name, "SliderBar", "")
	local bar = SystemData.ActiveWindow.name
	
	if (barName == "UiScale") then
		local uiScale =( SliderBarGetCurrentPosition( "UiScaleSliderBar" )/2 )+ 0.5
		LabelSetText( "UiScaleVal", wstring.format( L"%2.2f", uiScale ) )
		return
	end

	if (barName == "GenericGumpScale") then
		local genericGumpScale = ( ((SliderBarGetCurrentPosition("GenericGumpScaleSliderBar") * 0.115) + 0.885) * 1.2)		
		genericGumpScale = tonumber(string.format("%2.2f", genericGumpScale))		
		LabelSetText( "GenericGumpScaleVal", L""..genericGumpScale)		
		return
	end
	
	if (barName == "UiScale") then
		-- update the cache size value
		local cacheSize = math.floor( SliderBarGetCurrentPosition( "SettingsOptionsCacheSizeSliderBar" ) * 1024 )
		LabelSetText( "SettingsOptionsCacheSizeVal", L""..cacheSize )	
		return
	end

	MobilesOnScreen.OnSlide( curPos )
	
	
	
	if (barName == "BaseAlpha") then
		barVal = SliderBarGetCurrentPosition(bar )
		barVal = tonumber(string.format("%.2f", barVal))
		LabelSetText(barName .. "Val", L"" .. barVal)
		if (barVal < 0.01) then
			barVal = 0.01
			SliderBarSetCurrentPosition(barName .. "SliderBar", barVal )
			
			LabelSetText(barName .. "Val", L"" .. barVal)
		end
		
	elseif (barName == "FadeDelay") then
		
		barVal =  tonumber(string.format("%.0f", SliderBarGetCurrentPosition(bar ) * 20))
		LabelSetText(barName .. "Val", L"" .. barVal)
		if (barVal < 1) then
			barVal = 1
			SliderBarSetCurrentPosition(barName .. "SliderBar", barVal / 20 )
			LabelSetText(barName .. "Val", L"" .. barVal)
		end
		
	elseif (barName == "MinTotDamage") then
		barVal =  tonumber(string.format("%.0f", SliderBarGetCurrentPosition(bar ) * 1000))
		LabelSetText(barName .. "Val", L"" .. barVal)
		if (barVal < 1) then
			barVal = 1
			SliderBarSetCurrentPosition(barName .. "SliderBar", barVal / 1000 )
			LabelSetText(barName .. "Val", L"" .. barVal)
		end
		
	end
	
end

function SettingsWindow.UpdateSettings()
	
    --Debug.Print( "SettingsWindow.UpdateSettings" )
    
	local text
	
	-- Resolution
	
	for res = 1, table.getn( SystemData.AvailableResolutions.widths )do 
		if( SystemData.Settings.Resolution.fullScreen.width == SystemData.AvailableResolutions.widths[res] and 
			SystemData.Settings.Resolution.fullScreen.height == SystemData.AvailableResolutions.heights[res] )then
			ComboBoxSetSelectedMenuItem( "SettingsGraphicsFullScreenResCombo", res )
		end 
	end
	
	ComboBoxSetSelectedMenuItem( "SettingsGraphicsFramerateMaxCombo", (SystemData.Settings.Resolution.framerateMax / 10) - 1 )
	
	ComboBoxSetSelectedMenuItem( "SettingsGraphicsParticleLODCombo", SystemData.Settings.Resolution.particleLOD )
	ComboBoxSetSelectedMenuItem( "SettingsGraphicsParticleFilterCombo", SystemData.Settings.Resolution.particleFilter+1 )
	ComboBoxSetSelectedMenuItem( "SettingsGraphicsAnimationCombo", SystemData.Settings.Optimization.frameSetRestriction+1 )
	
	ButtonSetPressedFlag( "SettingsGraphicsShowFrameButton", SystemData.Settings.Resolution.showWindowFrame )
	ButtonSetPressedFlag( "SettingsGraphicsShowShadowsButton", SystemData.Settings.Resolution.showShadows )
	ButtonSetPressedFlag( "SettingsGraphicsEnableVSyncButton", SystemData.Settings.Resolution.enableVSync )
	ButtonSetPressedFlag( "SettingsGraphicsCircleOfTransparencyButton", SystemData.Settings.GameOptions.circleOfTransEnabled )
    ButtonSetPressedFlag( "SettingsGraphicsHardwareDeathEffectButton", SystemData.Settings.GameOptions.useHardwareDeathEffect )
	ButtonSetPressedFlag( "SettingsGraphicsUseFullscreenButton", SystemData.Settings.Resolution.useFullScreen )
	ButtonSetPressedFlag( "SettingsGraphicsPlayIdleAnimationButton", SystemData.Settings.Optimization.idleAnimation )
	ButtonSetPressedFlag( "SettingsGraphicsPlayFlyingAnimationButton", SystemData.Settings.Optimization.bEnableFlyingAnimation)
	ButtonSetPressedFlag( "SettingsGraphicsDisplayAllHouseContentsButton", SystemData.Settings.Optimization.bDisplayAllHouseContents)
	ButtonSetPressedFlag( "SettingsGraphicsShowFoliageButton", SystemData.Settings.Resolution.displayFoliage )
	
	-- Legacy
	ButtonSetPressedFlag( "SettingsLegacyUseLegacyContainersButton", SystemData.Settings.Interface.LegacyContainers )
	ButtonSetPressedFlag( "SettingsLegacyUseLegacyPaperdollsButton", SystemData.Settings.Interface.LegacyPaperdolls)
	ButtonSetPressedFlag( "LegacyChatButton", SystemData.Settings.Interface.LegacyChat )
	ButtonSetPressedFlag( "SettingsLegacyLegacyTargetingButton", SystemData.Settings.GameOptions.legacyTargeting )
	
	SliderBarSetCurrentPosition( "GammaSliderBar", SystemData.Settings.Resolution.gamma )
	LabelSetText( "GammaVal", wstring.format( L"%2.2f", SystemData.Settings.Resolution.gamma ) )
 
	--Language
	for lan = 1, SettingsWindow.NUM_LANGUAGES do 
		if( SystemData.Settings.Language.type == SettingsWindow.Languages[lan].id )then
			ComboBoxSetSelectedMenuItem( "SettingsOptionsLanguageCombo", lan )
		end
	end
    ButtonSetPressedFlag( "SettingsOptionsEnglishNamesButton", SystemData.Settings.Language.englishNames )
	
	--Cache Size
	SliderBarSetCurrentPosition( "SettingsOptionsCacheSizeSliderBar", (SystemData.Settings.Optimization.cacheSize / 1024) )
	LabelSetText( "SettingsOptionsCacheSizeVal",  L""..SystemData.Settings.Optimization.cacheSize )	
	
	for sn = 1, SettingsWindow.NUM_SHOWNAMES do 
		if( SystemData.Settings.GameOptions.showNames == SettingsWindow.ShowNames[sn].id )then
			ComboBoxSetSelectedMenuItem( "SettingsOptionsShowNamesCombo", sn )
		end
	end

	for sn = 1, SettingsWindow.NUM_LEGACYBACKPACKSTYLES do 
		if( SystemData.Settings.GameOptions.myLegacyBackpackType == SettingsWindow.LegacyBackpackStyle[sn].id )then
			ComboBoxSetSelectedMenuItem( "SettingsLegacyBackpackStyleCombo", sn )
		end
	end

	local filter
	for filter = 1, SettingsWindow.NUM_OBJHANDLE_FILTERS do
		if( SystemData.Settings.GameOptions.objectHandleFilter == SettingsWindow.ObjectHandles[filter].id )then
			ComboBoxSetSelectedMenuItem( "SettingsOptionsObjHandleFilterCombo", filter )
		end
	end	

	local skinItr
	for skinItr = 1, #SystemData.CustomUIList do
		if( SystemData.Settings.Interface.customUiName == SystemData.CustomUIList[skinItr] )then
			ComboBoxSetSelectedMenuItem( "CustomSkinsCombo", skinItr )
		end
	end
	
	local indexSize
	local objHandleSize
	for indexSize, objHandleSize in pairs( SettingsWindow.ObjectHandleSizes )do
		if( SystemData.Settings.GameOptions.objectHandleSize == objHandleSize )then
			ComboBoxSetSelectedMenuItem( "SettingsOptionsObjHandleSizeCombo", indexSize )
		end
	end
	
	if( SystemData.Settings.Interface.OverheadChatFadeDelay ~= nil )then
		ComboBoxSetSelectedMenuItem( "OverheadChatFadeDelayCombo", SystemData.Settings.Interface.OverheadChatFadeDelay )
	end
	
	-- Scroll Wheel Behavior
	SettingsWindow.RefreshScrollWheelComboBoxes()
	local scrollWheelBehaviors = SettingsWindow.ScrollWheelBehaviors
	local numScrollWheelBehaviors = SettingsWindow.NUM_SCROLLWHEELBEHAVIORS
	if ( ButtonGetPressedFlag( "SettingsLegacyLegacyTargetingButton" ) == true) then
		scrollWheelBehaviors = SettingsWindow.ScrollWheelBehaviors_Legacy
		numScrollWheelBehaviors = SettingsWindow.NUM_SCROLLWHEELBEHAVIORS_LEGACY
	end
	
	ComboBoxSetSelectedMenuItem( "SettingsKeyBindingsScrollWheelUpCombo", 1 ) -- Default case
	for behavior = 1, numScrollWheelBehaviors do
		if( SystemData.Settings.GameOptions.mouseScrollUpAction == scrollWheelBehaviors[behavior].id )then
			ComboBoxSetSelectedMenuItem( "SettingsKeyBindingsScrollWheelUpCombo", behavior )
		end
	end
	ComboBoxSetSelectedMenuItem( "SettingsKeyBindingsScrollWheelDownCombo", 1 ) -- Default case
	for behavior = 1, numScrollWheelBehaviors do
		if( SystemData.Settings.GameOptions.mouseScrollDownAction == scrollWheelBehaviors[behavior].id )then
			ComboBoxSetSelectedMenuItem( "SettingsKeyBindingsScrollWheelDownCombo", behavior )
		end
	end
	
    ComboBoxSetSelectedMenuItem( "ContainerViewCombo", 1)
	local containerMode = SystemData.Settings.Interface.defaultContainerMode
	for id, data in ipairs(SettingsWindow.ContainerViewOptions) do
	    if( data.name == containerMode ) then
	        ComboBoxSetSelectedMenuItem( "ContainerViewCombo", id)
	        break
	    end
	end
    
    ComboBoxSetSelectedMenuItem( "CorpseViewCombo", 1)
	local corpseMode = SystemData.Settings.Interface.defaultCorpseMode
	for id, data in ipairs(SettingsWindow.ContainerViewOptions) do
	    if( data.name == corpseMode ) then
	        ComboBoxSetSelectedMenuItem( "CorpseViewCombo", id)
	        break
	    end
	end	
	
	SliderBarSetCurrentPosition( "UiScaleSliderBar", ( ( SystemData.Settings.Interface.customUiScale - 0.5 )*2 ) )
	LabelSetText( "UiScaleVal", wstring.format( L"%2.2f", SystemData.Settings.Interface.customUiScale ) )

	SliderBarSetCurrentPosition( "GenericGumpScaleSliderBar", ((((SystemData.Settings.Interface.customGenericGumpScale) / 1.2) - 0.885) /0.115))	
	LabelSetText( "GenericGumpScaleVal", wstring.format( L"%2.2f", SystemData.Settings.Interface.customGenericGumpScale ) )	
	
	ButtonSetPressedFlag( "BadWordFilterOptionButton", SystemData.Settings.Profanity.BadWordFilter )
	ButtonSetPressedFlag( "IgnoreListOptionButton", SystemData.Settings.Profanity.IgnoreListFilter )
	ButtonSetPressedFlag( "IgnoreConfListOptionButton", SystemData.Settings.Profanity.IgnoreConfListFilter )
	
	ButtonSetPressedFlag( "AlwaysRunButton", SystemData.Settings.GameOptions.alwaysRun )
	ButtonSetPressedFlag( "EnableAutorunButton", SystemData.Settings.GameOptions.enableAutorun )
	ButtonSetPressedFlag( "EnablePathfindingButton", SystemData.Settings.GameOptions.enablePathfinding )
	ButtonSetPressedFlag( "QueryBeforeCriminalActionsButton", SystemData.Settings.GameOptions.queryBeforeCriminalAction )
	ButtonSetPressedFlag( "IgnoreMouseActionsOnSelfButton", SystemData.Settings.GameOptions.ignoreMouseActionsOnSelf )
	ButtonSetPressedFlag( "HoldShiftToUnstackButton", SystemData.Settings.GameOptions.holdShiftToUnstack )
	ButtonSetPressedFlag( "ShiftRightClickContextMenusButton", SystemData.Settings.GameOptions.shiftRightClickContextMenus )
	ButtonSetPressedFlag( "TargetQueueingButton", SystemData.Settings.GameOptions.targetQueueing )
	ButtonSetPressedFlag( "AlwaysAttackButton", SystemData.Settings.GameOptions.alwaysAttack )
	ButtonSetPressedFlag( "TooltipsButton", SystemData.Settings.Interface.showTooltips )
	ButtonSetPressedFlag( "PartyInvitePopUpButton", SystemData.Settings.Interface.partyInvitePopUp )
	ButtonSetPressedFlag( "TipoftheDayButton", SystemData.Settings.Interface.showTipoftheDay )
	ButtonSetPressedFlag( "ShowCorpseNamesButton", SystemData.Settings.GameOptions.showCorpseNames )
	ButtonSetPressedFlag( "ShowStrButton", SystemData.Settings.GameOptions.showStrLabel )
	ButtonSetPressedFlag( "OverheadChatButton", SystemData.Settings.Interface.OverheadChat )
	ButtonSetPressedFlag( "EnableChatLogButton", SystemData.Settings.GameOptions.enableChatLog )
	ButtonSetPressedFlag( "MasterVolumeToggleButton", SystemData.Settings.Sound.master.enabled )
	ButtonSetPressedFlag( "EffectsVolumeToggleButton", SystemData.Settings.Sound.effects.enabled )
	ButtonSetPressedFlag( "MusicVolumeToggleButton", SystemData.Settings.Sound.music.enabled )
	ButtonSetPressedFlag( "PlayFootstepsToggleButton", SystemData.Settings.Sound.footsteps.enabled )
	SliderBarSetCurrentPosition( "MasterVolumeSliderBar", SystemData.Settings.Sound.master.volume )
	SliderBarSetCurrentPosition( "EffectsVolumeSliderBar", SystemData.Settings.Sound.effects.volume )
	SliderBarSetCurrentPosition( "MusicVolumeSliderBar", SystemData.Settings.Sound.music.volume )
	
	SettingsWindow.UpdateKeyBindings()
	
	ButtonSetPressedFlag( "ToggleMapCombo" .. "Button", Interface.ShowMapCombos )
	ButtonSetPressedFlag( "ToggleWindowSnap" .. "Button", Interface.EnableSnapping )
	
	ButtonSetPressedFlag( "BlockOthersPaperdoll" .. "Button", Interface.BlockOthersPaperdoll	)
	
	ButtonSetPressedFlag( "BlockWarOnPets" .. "Button", SystemData.Settings.GameOptions.noWarOnPets	)
	ButtonSetPressedFlag( "BlockWarOnParty" .. "Button",SystemData.Settings.GameOptions.noWarOnParty )
	ButtonSetPressedFlag( "BlockWarOnGuild" .. "Button",SystemData.Settings.GameOptions.noWarOnFriendly )
	
	ButtonSetPressedFlag( "ToggleWarShield" .. "Button",Interface.WarShield )
	ButtonSetPressedFlag( "AutoIgnoreCorpses" .. "Button",ContainerWindow.EnableAutoIgnoreCorpses )
	
	ButtonSetPressedFlag( "IgnoreSummons" .. "Button",CenterScreenText.EnableIgnoreSummons)
	
	if (CenterScreenText.LowHPPercDisabled) then
		ComboBoxSetSelectedMenuItem( "LowHPCombo", 16 )
	elseif CenterScreenText.LowHPPerc <= 50 then
		ComboBoxSetSelectedMenuItem( "LowHPCombo", (CenterScreenText.LowHPPerc  / 5)  )
	elseif CenterScreenText.LowHPPerc == 60 then
		ComboBoxSetSelectedMenuItem( "LowHPCombo", 11  )
	elseif CenterScreenText.LowHPPerc == 70 then
		ComboBoxSetSelectedMenuItem( "LowHPCombo", 12  )
	elseif CenterScreenText.LowHPPerc == 80 then
		ComboBoxSetSelectedMenuItem( "LowHPCombo", 13  )
	elseif CenterScreenText.LowHPPerc == 90 then
		ComboBoxSetSelectedMenuItem( "LowHPCombo", 14  )
	elseif CenterScreenText.LowHPPerc == 99 then
		ComboBoxSetSelectedMenuItem( "LowHPCombo", 15  )
	end
	
	if (CenterScreenText.LowHPPETPercDisabled) then
		ComboBoxSetSelectedMenuItem( "LowHPPetCombo", 16 )
	elseif CenterScreenText.LowPETHPPerc <= 50 then
		ComboBoxSetSelectedMenuItem( "LowHPPetCombo", (CenterScreenText.LowPETHPPerc  / 5)  )
	elseif CenterScreenText.LowPETHPPerc == 60 then
		ComboBoxSetSelectedMenuItem( "LowHPPetCombo", 11  )
	elseif CenterScreenText.LowPETHPPerc == 70 then
		ComboBoxSetSelectedMenuItem( "LowHPPetCombo", 12  )
	elseif CenterScreenText.LowPETHPPerc == 80 then
		ComboBoxSetSelectedMenuItem( "LowHPPetCombo", 13  )
	elseif CenterScreenText.LowPETHPPerc == 90 then
		ComboBoxSetSelectedMenuItem( "LowHPPetCombo", 14  )
	elseif CenterScreenText.LowPETHPPerc == 99 then
		ComboBoxSetSelectedMenuItem( "LowHPPetCombo", 15  )
	end
	
	ComboBoxSetSelectedMenuItem( "StatusWindowStyleCombo", Interface.StatusWindowStyle + 1  )
	
	
	ButtonSetPressedFlag( "ToggleWindowSnap" .. "Button", Interface.EnableSnapping )
	
	ButtonSetPressedFlag( "ToggleContentsInfo" .. "Button", Interface.ToggleContentsInfo )
	ButtonSetPressedFlag( "ToggleGridLegacy" .. "Button", Interface.GridLegacy )
	ButtonSetPressedFlag( "ToggleGrid" .. "Button", Interface.EnableContainerGrid )
	ButtonSetPressedFlag( "ToggleAlternateGrid" .. "Button", Interface.AlternateGrid )
	ButtonSetPressedFlag( "ToggleExtraBright" .. "Button", Interface.ExtraBrightContainers )
	WindowSetTintColor( "ContainerGridColor" .. "Button", ContainerWindow.BaseGridColor.r,ContainerWindow.BaseGridColor.g,ContainerWindow.BaseGridColor.b)
	WindowSetTintColor( "ContainerGridAlternateColor" .. "Button", ContainerWindow.AlternateBackpack.r,ContainerWindow.AlternateBackpack.g,ContainerWindow.AlternateBackpack.b)
	
	ButtonSetPressedFlag( "HealthbarsButtons" .. "Button", Interface.StatusButtons )
	ButtonSetPressedFlag( "ToggleNotorietyAura" .. "Button", Interface.AuraEnabled )
	
	ButtonSetPressedFlag( "ToggleMobileArrow" .. "Button", Interface.EnableMobileArrow )
	ButtonSetPressedFlag( "LegacyCloseStyle" .. "Button", MobileHealthBar.LegacyCloseStyle )
	ButtonSetPressedFlag( "PetLegacyCloseStyle" .. "Button", MobileHealthBar.PetLegacyCloseStyle )
	
	ButtonSetPressedFlag( "ShowCloseExtract" .. "Button", Interface.ShowCloseExtract )
	ButtonSetPressedFlag( "HealthBarWod" .. "Button", Interface.HealthBarWod )
	
	ComboBoxClearMenuItems( "Red" )
	local sel = 1
	for i = 1 , table.getn(Interface.RedButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.RedButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Red", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Red", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.RedButtonSpells[i].SpellId == Interface.RedButton) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Red", sel )
	
	ComboBoxClearMenuItems( "Red2" )
	local sel = 1
	for i = 1 , table.getn(Interface.RedButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.RedButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Red2", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Red2", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.RedButtonSpells[i].SpellId == Interface.RedButton2) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Red2", sel )
	
	ComboBoxClearMenuItems( "Red3" )
	local sel = 1
	for i = 1 , table.getn(Interface.RedButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.RedButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Red3", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Red3", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.RedButtonSpells[i].SpellId == Interface.RedButton3) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Red3", sel )
	
	sel = 1
	ComboBoxClearMenuItems( "Green" )
	for i = 1 , table.getn(Interface.GreenButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.GreenButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Green", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Green", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.GreenButtonSpells[i].SpellId == Interface.GreenButton) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Green", sel )
	
	sel = 1
	ComboBoxClearMenuItems( "Green2" )
	for i = 1 , table.getn(Interface.GreenButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.GreenButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Green2", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Green2", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.GreenButtonSpells[i].SpellId == Interface.GreenButton2) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Green2", sel )
	
	sel = 1
	ComboBoxClearMenuItems( "Green3" )
	for i = 1 , table.getn(Interface.GreenButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.GreenButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Green3", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Green3", wstring.sub(Interface.GreenButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.GreenButtonSpells[i].SpellId == Interface.GreenButton3) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Green3", sel )

	sel = 1
	ComboBoxClearMenuItems( "Blue" )
	for i = 1 , table.getn(Interface.BlueButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.BlueButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Blue", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Blue", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.BlueButtonSpells[i].SpellId == Interface.BlueButton) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Blue", sel )
	
	sel = 1
	ComboBoxClearMenuItems( "Blue2" )
	for i = 1 , table.getn(Interface.BlueButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.BlueButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Blue2", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Blue2", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.BlueButtonSpells[i].SpellId == Interface.BlueButton2) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Blue2", sel )
	
	sel = 1
	ComboBoxClearMenuItems( "Blue3" )
	for i = 1 , table.getn(Interface.BlueButtonSpells) do
		local icon, serverId, tid, desctid = GetAbilityData(Interface.BlueButtonSpells[i].SpellId)
		if (tid) then
			ComboBoxAddMenuItem( "Blue3", wstring.sub(GetStringFromTid(tid),1,14)  )
		else
			ComboBoxAddMenuItem( "Blue3", wstring.sub(Interface.BlueButtonSpells[i].AltText,1,14)  )
		end
		if (Interface.BlueButtonSpells[i].SpellId == Interface.BlueButton3) then
			sel = i
		end
	end
	ComboBoxSetSelectedMenuItem( "Blue3", sel )
	
	ButtonSetPressedFlag( "clickableNames" .. "Button", OverheadText.clickableNames )
	
	ButtonSetPressedFlag( "DisableSpells" .. "Button", Interface.DisableSpells )
	ButtonSetPressedFlag( "ShowSpellName" .. "Button", Interface.ShowSpellName )
	ButtonSetPressedFlag( "noPoisonOthers" .. "Button", Interface.noPoisonOthers )
	
	WindowSetTintColor("OverheadTextOptions" .. "colorHeal" .. "Button", TextParsing.Heal.r,TextParsing.Heal.g,TextParsing.Heal.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorCurse" .. "Button", TextParsing.Curse.r,TextParsing.Curse.g,TextParsing.Curse.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorPara" .. "Button", TextParsing.Paralyze.r,TextParsing.Paralyze.g,TextParsing.Paralyze.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorNeutral" .. "Button", TextParsing.Neutral.r,TextParsing.Neutral.g,TextParsing.Neutral.b)
	
	WindowSetTintColor("OverheadTextOptions" .. "colorNeg" .. "Button", TextParsing.OverHeadError.r,TextParsing.OverHeadError.g,TextParsing.OverHeadError.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorPos" .. "Button", TextParsing.SpecialColor.r,TextParsing.SpecialColor.g,TextParsing.SpecialColor.b)
	
	WindowSetTintColor("OverheadTextOptions" .. "colorYou" .. "Button", DamageWindow.YOUGETAMAGE_COLOR.r,DamageWindow.YOUGETAMAGE_COLOR.g,DamageWindow.YOUGETAMAGE_COLOR.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorPet" .. "Button", DamageWindow.PETGETDAMAGE_COLOR.r,DamageWindow.PETGETDAMAGE_COLOR.g,DamageWindow.PETGETDAMAGE_COLOR.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorEnemy" .. "Button", DamageWindow.OTHERGETDAMAGE_COLOR.r,DamageWindow.OTHERGETDAMAGE_COLOR.g,DamageWindow.OTHERGETDAMAGE_COLOR.b)
	
	WindowSetTintColor("OverheadTextOptions" .. "colorPhys" .. "Button", SpellsInfo.PHYSICAL.r,SpellsInfo.PHYSICAL.g,SpellsInfo.PHYSICAL.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorFire" .. "Button", SpellsInfo.FIRE.r,SpellsInfo.FIRE.g,SpellsInfo.FIRE.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorCold" .. "Button", SpellsInfo.COLD.r,SpellsInfo.COLD.g,SpellsInfo.COLD.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorPois" .. "Button", SpellsInfo.POISON.r,SpellsInfo.POISON.g,SpellsInfo.POISON.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorEner" .. "Button", SpellsInfo.ENERGY.r,SpellsInfo.ENERGY.g,SpellsInfo.ENERGY.b)
	WindowSetTintColor("OverheadTextOptions" .. "colorChaos" .. "Button", SpellsInfo.Chaos.r,SpellsInfo.Chaos.g,SpellsInfo.Chaos.b)
end

function SettingsWindow.UpdateKeyBindings()
	for key = 1, table.getn( SettingsWindow.Keybindings )do
		if( SettingsWindow.Keybindings[key].type ~= nil )then
			if( SettingsWindow.Keybindings[key].newValue ~= nil )then
				SystemData.Settings.Keybindings[SettingsWindow.Keybindings[key].type] = SettingsWindow.Keybindings[key].newValue
				SettingsWindow.Keybindings[key].newValue = nil
			end
			
			LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "ActionValue", 255, 255, 255 )
			LabelSetText( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name.."ActionValue", SystemData.Settings.Keybindings[SettingsWindow.Keybindings[key].type] )
		end
	end	

	SettingsWindow.UpdateLegacyTargetBindingsText()
end

--When the Legacy or MMO Key Binding button has been selected, update the key binding to reflect the change
function SettingsWindow.OnDefaultKeyPressed()
	local buttonId = WindowGetId( WindowGetParent( SystemData.ActiveWindow.name ) )
	--Legacy Key Bindings have been selected
	if( buttonId == 1 )then
		local yesButton = { textTid = SettingsWindow.TID_YES, callback = function()SettingsWindow.ResetLegacyKeyBindings()end }
		local noButton = { textTid = SettingsWindow.TID_NO }
		local windowData = 
		{
			windowName = "Root", 
			titleTid = SettingsWindow.TID_INFO, 
			bodyTid = SettingsWindow.TID_RESETDEFAULTBINDINGS, 
			buttons = { yesButton, noButton }
		}
		UO_StandardDialog.CreateDialog( windowData )
		return
	end
	--MMO Key Bindings have been selected
	if( buttonId == 2 )then
		local yesButton = { textTid = SettingsWindow.TID_YES, callback = function()SettingsWindow.ResetMMOKeyBindings()end }
		local noButton = { textTid = SettingsWindow.TID_NO }
		local windowData = 
		{
			windowName = "Root", 
			titleTid = SettingsWindow.TID_INFO, 
			bodyTid = SettingsWindow.TID_RESETDEFAULTBINDINGS, 
			buttons = { yesButton, noButton }
		}
		UO_StandardDialog.CreateDialog( windowData )
		return
	end
	
end

--Set the key bindings to Legacy default
function SettingsWindow.ResetLegacyKeyBindings()
	ResetLegacyKeyBinding()
	
	for key = 1, table.getn( SettingsWindow.Keybindings )do
		if( SettingsWindow.Keybindings[key].type ~= nil )then
			local value = SystemData.Settings.DefaultKeybindings[SettingsWindow.Keybindings[key].type]
			if( value ~= nil )then
				SettingsWindow.Keybindings[key].newValue = value
				LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "ActionValue", 255, 255, 255 )
				LabelSetText( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name.."ActionValue", value )
			end
		end
	end
	
	SettingsWindow.UpdateLegacyTargetBindingsText()
end

--Set the key bindings to MMO default
function SettingsWindow.ResetMMOKeyBindings()
	ResetMMOKeyBinding()
	
	for key = 1, table.getn( SettingsWindow.Keybindings )do
		if( SettingsWindow.Keybindings[key].type ~= nil )then
			local value = SystemData.Settings.DefaultKeybindings[SettingsWindow.Keybindings[key].type]
			if( value ~= nil )then
				SettingsWindow.Keybindings[key].newValue = value
				LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "ActionValue", 255, 255, 255 )
				LabelSetText( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name.."ActionValue", value )
			end
		end
	end
	
	SettingsWindow.UpdateLegacyTargetBindingsText()
end

function SettingsWindow.UpdateLegacyTargetBindingsText()
	if( SystemData.Settings.GameOptions.legacyTargeting ) then
		for key = SettingsWindow.NON_LEGACY_BINDING_MIN, SettingsWindow.NON_LEGACY_BINDING_MAX do
			LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "ActionValue", 128, 128, 128 )
			LabelSetText( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name.."ActionValue", GetStringFromTid(SettingsWindow.TID.NotAvailable) )
		end
	end
end

function SettingsWindow.OnOkayButton()
	SettingsWindow.OnApplyButton()

	-- Close the window		
	ToggleWindowByName( "SettingsWindow", "", nil )
end

function SettingsWindow.OnApplyButton()

	-- Set the Options
		
	local fullScreenRes = ComboBoxGetSelectedMenuItem( "SettingsGraphicsFullScreenResCombo" )
	SystemData.Settings.Resolution.fullScreen.width = SystemData.AvailableResolutions.widths[fullScreenRes]
	SystemData.Settings.Resolution.fullScreen.height = SystemData.AvailableResolutions.heights[fullScreenRes]
	
	SystemData.Settings.Resolution.framerateMax = ( ComboBoxGetSelectedMenuItem( "SettingsGraphicsFramerateMaxCombo" ) + 1 ) * 10
	
	SystemData.Settings.Resolution.showWindowFrame = ButtonGetPressedFlag( "SettingsGraphicsShowFrameButton" )
	SystemData.Settings.Resolution.showShadows = ButtonGetPressedFlag( "SettingsGraphicsShowShadowsButton" )
	SystemData.Settings.Resolution.enableVSync = ButtonGetPressedFlag( "SettingsGraphicsEnableVSyncButton" )
	SystemData.Settings.GameOptions.circleOfTransEnabled = ButtonGetPressedFlag( "SettingsGraphicsCircleOfTransparencyButton" )
    SystemData.Settings.GameOptions.useHardwareDeathEffect = ButtonGetPressedFlag( "SettingsGraphicsHardwareDeathEffectButton" )
	SystemData.Settings.Resolution.useFullScreen = ButtonGetPressedFlag( "SettingsGraphicsUseFullscreenButton" )
	SystemData.Settings.Optimization.idleAnimation = ButtonGetPressedFlag( "SettingsGraphicsPlayIdleAnimationButton" )
	SystemData.Settings.Optimization.bEnableFlyingAnimation = ButtonGetPressedFlag( "SettingsGraphicsPlayFlyingAnimationButton" )
	SystemData.Settings.Optimization.bDisplayAllHouseContents = ButtonGetPressedFlag( "SettingsGraphicsDisplayAllHouseContentsButton" )
	SystemData.Settings.Resolution.displayFoliage = ButtonGetPressedFlag( "SettingsGraphicsShowFoliageButton" )	

	SystemData.Settings.Resolution.gamma = SliderBarGetCurrentPosition( "GammaSliderBar" )
	
	SystemData.Settings.Resolution.particleLOD = ComboBoxGetSelectedMenuItem( "SettingsGraphicsParticleLODCombo" )
	SystemData.Settings.Resolution.particleFilter = ComboBoxGetSelectedMenuItem( "SettingsGraphicsParticleFilterCombo" )-1

	SystemData.Settings.Optimization.frameSetRestriction = ComboBoxGetSelectedMenuItem( "SettingsGraphicsAnimationCombo" )-1

	-- Language
	local languageIndex = ComboBoxGetSelectedMenuItem( "SettingsOptionsLanguageCombo" )
	SystemData.Settings.Language.type = SettingsWindow.Languages[languageIndex].id
    SystemData.Settings.Language.englishNames = ButtonGetPressedFlag( "SettingsOptionsEnglishNamesButton" )
	
	-- Cache Size
	SystemData.Settings.Optimization.cacheSize = (SliderBarGetCurrentPosition( "SettingsOptionsCacheSizeSliderBar" ) * 1024)
	
	-- Show Names
	local showNamesIndex = ComboBoxGetSelectedMenuItem( "SettingsOptionsShowNamesCombo" )
	SystemData.Settings.GameOptions.showNames = SettingsWindow.ShowNames[showNamesIndex].id

	--Backpack Style
	local backpackTypeIndex = ComboBoxGetSelectedMenuItem( "SettingsLegacyBackpackStyleCombo" )
	local beforePack = SystemData.Settings.GameOptions.myLegacyBackpackType
	SystemData.Settings.GameOptions.myLegacyBackpackType = SettingsWindow.LegacyBackpackStyle[backpackTypeIndex].id	
	local containerReload = false
	if(ContainerWindow.PlayerBackpack and beforePack ~= SystemData.Settings.GameOptions.myLegacyBackpackType and (SystemData.Settings.Interface.LegacyContainers or Interface.GridLegacy))then		
		local playerbackpackWindow = "ContainerWindow_"..ContainerWindow.PlayerBackpack
		if WindowGetShowing(playerbackpackWindow) then
			WindowSetShowing(playerbackpackWindow,false)			
		end
		DestroyWindow(playerbackpackWindow)
		UnregisterWindowData(WindowData.ContainerWindow.Type, ContainerWindow.PlayerBackpack)			
	end

	
	-- Sound 
	SystemData.Settings.Sound.master.enabled = ButtonGetPressedFlag( "MasterVolumeToggleButton" )
	SystemData.Settings.Sound.master.volume = SliderBarGetCurrentPosition( "MasterVolumeSliderBar" )
	
	SystemData.Settings.Sound.effects.enabled = ButtonGetPressedFlag( "EffectsVolumeToggleButton" )
	SystemData.Settings.Sound.effects.volume = SliderBarGetCurrentPosition( "EffectsVolumeSliderBar" )
	
	SystemData.Settings.Sound.music.enabled = ButtonGetPressedFlag( "MusicVolumeToggleButton" )
	SystemData.Settings.Sound.music.volume = SliderBarGetCurrentPosition( "MusicVolumeSliderBar" )

	SystemData.Settings.Sound.footsteps.enabled = ButtonGetPressedFlag( "PlayFootstepsToggleButton" )
	
	-- Options
	SystemData.Settings.GameOptions.alwaysRun = ButtonGetPressedFlag( "AlwaysRunButton" )
	SystemData.Settings.GameOptions.enableAutorun = ButtonGetPressedFlag( "EnableAutorunButton" )
	SystemData.Settings.GameOptions.enablePathfinding = ButtonGetPressedFlag( "EnablePathfindingButton" )
	SystemData.Settings.GameOptions.queryBeforeCriminalAction = ButtonGetPressedFlag( "QueryBeforeCriminalActionsButton" )
	SystemData.Settings.GameOptions.ignoreMouseActionsOnSelf = ButtonGetPressedFlag( "IgnoreMouseActionsOnSelfButton" )
	SystemData.Settings.GameOptions.holdShiftToUnstack = ButtonGetPressedFlag( "HoldShiftToUnstackButton" )
	SystemData.Settings.GameOptions.shiftRightClickContextMenus = ButtonGetPressedFlag( "ShiftRightClickContextMenusButton" )
	SystemData.Settings.GameOptions.targetQueueing = ButtonGetPressedFlag( "TargetQueueingButton" )
	SystemData.Settings.GameOptions.alwaysAttack = ButtonGetPressedFlag( "AlwaysAttackButton" )
	SystemData.Settings.GameOptions.showCorpseNames = ButtonGetPressedFlag( "ShowCorpseNamesButton" )
	SystemData.Settings.GameOptions.showStrLabel = ButtonGetPressedFlag( "ShowStrButton" )
	Interface.SaveBoolean( "StatusLabels", SystemData.Settings.GameOptions.showStrLabel )
	
	-- Object Handle Filter
	local filterIndex = ComboBoxGetSelectedMenuItem( "SettingsOptionsObjHandleFilterCombo" )	
	SystemData.Settings.GameOptions.objectHandleFilter = SettingsWindow.ObjectHandles[filterIndex].id	
	
	local skinIndex = ComboBoxGetSelectedMenuItem( "CustomSkinsCombo" )
	SystemData.Settings.Interface.customUiName = SystemData.CustomUIList[skinIndex]
	
	local objHandleSize = ComboBoxGetSelectedMenuItem( "SettingsOptionsObjHandleSizeCombo" )
	SystemData.Settings.GameOptions.objectHandleSize = SettingsWindow.ObjectHandleSizes[objHandleSize]
	
	-- Interface
	SystemData.Settings.Interface.showTooltips = ButtonGetPressedFlag( "TooltipsButton" )
	SystemData.Settings.Interface.partyInvitePopUp = ButtonGetPressedFlag( "PartyInvitePopUpButton" )
	SystemData.Settings.Interface.showTipoftheDay = ButtonGetPressedFlag( "TipoftheDayButton" )
	--SystemData.Settings.Interface.ShowChatWindow = ButtonGetPressedFlag( "ShowChatWindowButton" )

	SystemData.Settings.Interface.OverheadChat = ButtonGetPressedFlag( "OverheadChatButton" )
	SystemData.Settings.Interface.OverheadChatFadeDelay = ComboBoxGetSelectedMenuItem( "OverheadChatFadeDelayCombo" )

	-- only update the scale if necesary
	local uiScale =( SliderBarGetCurrentPosition( "UiScaleSliderBar" )/2 )+ 0.5
	SystemData.Settings.Interface.customUiScale = uiScale

	local genericGumpScale = ( ((SliderBarGetCurrentPosition("GenericGumpScaleSliderBar") * 0.115) + 0.885) * 1.2)
	SystemData.Settings.Interface.customGenericGumpScale = genericGumpScale


    local selectedId = ComboBoxGetSelectedMenuItem( "ContainerViewCombo" )
    SystemData.Settings.Interface.defaultContainerMode = SettingsWindow.ContainerViewOptions[selectedId].name

    selectedId = ComboBoxGetSelectedMenuItem( "CorpseViewCombo" )
    SystemData.Settings.Interface.defaultCorpseMode = SettingsWindow.ContainerViewOptions[selectedId].name
	
    
    -- Legacy
    local beforeContainers = SystemData.Settings.Interface.LegacyContainers
    SystemData.Settings.Interface.LegacyChat = ButtonGetPressedFlag( "LegacyChatButton" )
    SystemData.Settings.Interface.LegacyContainers = ButtonGetPressedFlag( "SettingsLegacyUseLegacyContainersButton" )
	SystemData.Settings.Interface.LegacyPaperdolls = ButtonGetPressedFlag( "SettingsLegacyUseLegacyPaperdollsButton" )
    SystemData.Settings.GameOptions.legacyTargeting = ButtonGetPressedFlag( "SettingsLegacyLegacyTargetingButton" )
    SystemData.Settings.GameOptions.enableChatLog = ButtonGetPressedFlag( "EnableChatLogButton" )

	-- Profanity
	SystemData.Settings.Profanity.BadWordFilter = ButtonGetPressedFlag( "BadWordFilterOptionButton" )
	SystemData.Settings.Profanity.IgnoreListFilter = ButtonGetPressedFlag( "IgnoreListOptionButton" )
	SystemData.Settings.Profanity.IgnoreConfListFilter = ButtonGetPressedFlag( "IgnoreConfListOptionButton" )
	
	-- Key Bindings
	SettingsWindow.UpdateKeyBindings()
	
	-- Scroll Wheel Behavior
	local scrollWheelBehaviors = SettingsWindow.ScrollWheelBehaviors
	if ( ButtonGetPressedFlag( "SettingsLegacyLegacyTargetingButton" ) == true) then
		scrollWheelBehaviors = SettingsWindow.ScrollWheelBehaviors_Legacy
	end
	
	SystemData.Settings.GameOptions.mouseScrollUpAction = scrollWheelBehaviors[ComboBoxGetSelectedMenuItem( "SettingsKeyBindingsScrollWheelUpCombo" )].id
	SystemData.Settings.GameOptions.mouseScrollDownAction = scrollWheelBehaviors[ComboBoxGetSelectedMenuItem( "SettingsKeyBindingsScrollWheelDownCombo" )].id
	

	MapWindow.ToggleCombos(ButtonGetPressedFlag( "ToggleMapComboButton" ))

	Interface.BlockOthersPaperdoll = ButtonGetPressedFlag( "BlockOthersPaperdoll" .. "Button" )
	Interface.SaveBoolean( "BlockOthersPaperdoll" , Interface.BlockOthersPaperdoll )
	
	SystemData.Settings.GameOptions.noWarOnPets = ButtonGetPressedFlag( "BlockWarOnPets" .. "Button"  )
	Interface.SaveBoolean( "noWarOnPets" , SystemData.Settings.GameOptions.noWarOnPets )
	SystemData.Settings.GameOptions.noWarOnParty = ButtonGetPressedFlag( "BlockWarOnParty" .. "Button"  )
	Interface.SaveBoolean( "noWarOnParty" , SystemData.Settings.GameOptions.noWarOnParty )
	SystemData.Settings.GameOptions.noWarOnFriendly = ButtonGetPressedFlag( "BlockWarOnGuild" .. "Button"  )
	Interface.SaveBoolean( "noWarOnFriendly" , SystemData.Settings.GameOptions.noWarOnFriendly )
	
	Interface.WarShield = ButtonGetPressedFlag( "ToggleWarShield" .. "Button"  )
	Interface.SaveBoolean( "WarShield" , Interface.WarShield )
	WindowSetShowing("WarShield",Interface.WarShield)

	ContainerWindow.EnableAutoIgnoreCorpses = ButtonGetPressedFlag( "AutoIgnoreCorpses" .. "Button"  )
	Interface.SaveBoolean( "AutoIgnoreCorpses" , ContainerWindow.EnableAutoIgnoreCorpses)
	
	local lowHP = ComboBoxGetSelectedMenuItem( "LowHPCombo" )
	CenterScreenText.LowHPPerc = 35
	CenterScreenText.LowHPPercDisabled = false
	if lowHP <= 10 then
		CenterScreenText.LowHPPerc = lowHP * 5
	elseif lowHP == 11 then
		CenterScreenText.LowHPPerc = 60
	elseif lowHP == 12 then
		CenterScreenText.LowHPPerc = 70
	elseif lowHP == 13 then
		CenterScreenText.LowHPPerc = 80
	elseif lowHP == 14 then
		CenterScreenText.LowHPPerc = 90
	elseif lowHP == 15 then
		CenterScreenText.LowHPPerc = 99
	elseif lowHP == 16 then
		CenterScreenText.LowHPPercDisabled = true
		if CenterScreenText.LOWHPMEStarted then
			CenterScreenText.LOWHPMEStarted = false
			WindowStopAlphaAnimation("CenterScreenTextImage")
			WindowSetAlpha("CenterScreenTextImage", 0)
		end
	end
	Interface.SaveNumber( "LowHPPerc" , CenterScreenText.LowHPPerc )
	Interface.SaveBoolean( "LowHPPercDisabled" , CenterScreenText.LowHPPercDisabled )
	
	local lowHPPet = ComboBoxGetSelectedMenuItem( "LowHPPetCombo" )
	CenterScreenText.LowPETHPPerc = 35
	CenterScreenText.LowPETHPPercDisabled = false
	if lowHPPet <= 10 then
		CenterScreenText.LowPETHPPerc = lowHPPet * 5
	elseif lowHPPet == 11 then
		CenterScreenText.LowPETHPPerc = 60
	elseif lowHPPet == 12 then
		CenterScreenText.LowPETHPPerc = 70
	elseif lowHPPet == 13 then
		CenterScreenText.LowPETHPPerc = 80
	elseif lowHPPet == 14 then
		CenterScreenText.LowPETHPPerc = 90
	elseif lowHPPet == 15 then
		CenterScreenText.LowPETHPPerc = 99
	elseif lowHPPet == 16 then
		CenterScreenText.LowPETHPPercDisabled = true
		if CenterScreenText.LOWHPPetStarted then
			CenterScreenText.LOWHPPetStarted = false
			WindowStopAlphaAnimation("CenterScreenTextImage")
			WindowSetAlpha("CenterScreenTextImage", 0)
		end
	end
	
	Interface.SaveNumber( "LowPETHPPerc" , CenterScreenText.LowPETHPPerc )
	Interface.SaveBoolean( "LowPETHPPercDisabled" , CenterScreenText.LowPETHPPercDisabled )
	
	CenterScreenText.EnableIgnoreSummons = ButtonGetPressedFlag( "IgnoreSummons" .. "Button" )
	Interface.SaveBoolean( "EnableIgnoreSummons" , CenterScreenText.EnableIgnoreSummons )
	
	StatusWindow.ChangeStyle( ComboBoxGetSelectedMenuItem( "StatusWindowStyleCombo" ) - 1 )
	
	
	Interface.EnableSnapping = ButtonGetPressedFlag( "ToggleWindowSnap" .. "Button" )
	Interface.SaveBoolean( "EnableSnapping" , Interface.EnableSnapping )
	
	Interface.ToggleContentsInfo = ButtonGetPressedFlag( "ToggleContentsInfo" .. "Button" )
	Interface.SaveBoolean( "ToggleContentsInfo" , Interface.ToggleContentsInfo )
	
	containerReload = containerReload or Interface.GridLegacy ~= ButtonGetPressedFlag( "ToggleGridLegacy" .. "Button" )
	Interface.GridLegacy = ButtonGetPressedFlag( "ToggleGridLegacy" .. "Button" )
	Interface.SaveBoolean( "GridLegacy" , Interface.GridLegacy )
	
	containerReload = containerReload or Interface.EnableContainerGrid ~= ButtonGetPressedFlag( "ToggleGrid" .. "Button" )
	Interface.EnableContainerGrid = ButtonGetPressedFlag( "ToggleGrid" .. "Button" )
	Interface.SaveBoolean( "EnableContainerGrid" , Interface.EnableContainerGrid )
	
	containerReload = containerReload or Interface.AlternateGrid ~= ButtonGetPressedFlag( "ToggleAlternateGrid" .. "Button" )
	Interface.AlternateGrid = ButtonGetPressedFlag( "ToggleAlternateGrid" .. "Button" )
	Interface.SaveBoolean( "AlternateGrid" , Interface.AlternateGrid )
	
	containerReload = containerReload or Interface.ExtraBrightContainers ~= ButtonGetPressedFlag( "ToggleExtraBright" .. "Button" )
	Interface.ExtraBrightContainers = ButtonGetPressedFlag( "ToggleExtraBright" .. "Button" )
	Interface.SaveBoolean( "ExtraBrightContainers" , Interface.ExtraBrightContainers )
	
	Interface.StatusButtons = ButtonGetPressedFlag( "HealthbarsButtons" .. "Button" )
	Interface.SaveBoolean( "StatusButtons" , Interface.StatusButtons )
	StatusWindow.ToggleButtons()
	
	Interface.AuraEnabled = ButtonGetPressedFlag( "ToggleNotorietyAura" .. "Button" )
	Interface.SaveBoolean( "AuraEnabled" , Interface.AuraEnabled )
	
	Interface.EnableMobileArrow = ButtonGetPressedFlag( "ToggleMobileArrow" .. "Button" )
	Interface.SaveBoolean( "EnableMobileArrow" , Interface.EnableMobileArrow )
	if (DoesWindowNameExist("MobileArrow") and not Interface.EnableMobileArrow) then
		DetachWindowFromWorldObject( Interface.MobileArrowOver, "MobileArrow" )
		DestroyWindow("MobileArrow")
	end
	
	MobileHealthBar.LegacyCloseStyle =	ButtonGetPressedFlag( "LegacyCloseStyle" .. "Button" )				
	Interface.SaveBoolean( "LegacyCloseStyle", MobileHealthBar.LegacyCloseStyle ) 
	MobileHealthBar.PetLegacyCloseStyle =	ButtonGetPressedFlag( "PetLegacyCloseStyle" .. "Button" )			
	Interface.SaveBoolean( "PetLegacyCloseStyle", MobileHealthBar.PetLegacyCloseStyle ) 
	
	local updateHotbars = Interface.ShowCloseExtract ~=	ButtonGetPressedFlag( "ShowCloseExtract" .. "Button" )	
	Interface.ShowCloseExtract =	ButtonGetPressedFlag( "ShowCloseExtract" .. "Button" )			
	Interface.SaveBoolean( "ShowCloseExtract", Interface.ShowCloseExtract ) 
	
	updateHealthbars = updateHotbars or Interface.PetLegacyCloseStyle ~= ButtonGetPressedFlag( "HealthBarWod" .. "Button" )
	Interface.PetLegacyCloseStyle =	ButtonGetPressedFlag( "HealthBarWod" .. "Button" )			
	Interface.SaveBoolean( "HealthBarWod", Interface.HealthBarWod ) 
	
	local i = ComboBoxGetSelectedMenuItem( "Red" )
	Interface.RedButton = Interface.RedButtonSpells[i].SpellId
	Interface.SaveNumber( "RedButton", Interface.RedButton )
	
	local i = ComboBoxGetSelectedMenuItem( "Red2" )
	Interface.RedButton2 = Interface.RedButtonSpells[i].SpellId
	Interface.SaveNumber( "RedButton2", Interface.RedButton2 )
	
	local i = ComboBoxGetSelectedMenuItem( "Red3" )
	Interface.RedButton3 = Interface.RedButtonSpells[i].SpellId
	Interface.SaveNumber( "RedButton3", Interface.RedButton3 )
	
	
	i = ComboBoxGetSelectedMenuItem( "Green" )
	Interface.GreenButton = Interface.GreenButtonSpells[i].SpellId
	Interface.SaveNumber( "GreenButton", Interface.GreenButton )
	
	i = ComboBoxGetSelectedMenuItem( "Green2" )
	Interface.GreenButton2 = Interface.GreenButtonSpells[i].SpellId
	Interface.SaveNumber( "GreenButton2", Interface.GreenButton2 )
	
	i = ComboBoxGetSelectedMenuItem( "Green3" )
	Interface.GreenButton3 = Interface.GreenButtonSpells[i].SpellId
	Interface.SaveNumber( "GreenButton3", Interface.GreenButton3 )
	
	
	i = ComboBoxGetSelectedMenuItem( "Blue" )
	Interface.BlueButton = Interface.BlueButtonSpells[i].SpellId
	Interface.SaveNumber( "BlueButton", Interface.BlueButton )
	
	i = ComboBoxGetSelectedMenuItem( "Blue2" )
	Interface.BlueButton2 = Interface.BlueButtonSpells[i].SpellId
	Interface.SaveNumber( "BlueButton2", Interface.BlueButton2 )
	
	i = ComboBoxGetSelectedMenuItem( "Blue3" )
	Interface.BlueButton3 = Interface.BlueButtonSpells[i].SpellId
	Interface.SaveNumber( "BlueButton3", Interface.BlueButton3 )
	
	if (updateHealthbars) then
		for key, value in pairs(MobileHealthBar.hasWindow) do
			MobileHealthBar.UpdateStatus(key)
		end
	end
	
	OverheadText.clickableNames =	ButtonGetPressedFlag( "clickableNames" .. "Button" )			
	Interface.SaveBoolean( "clickableNames", OverheadText.clickableNames ) 
	
	Interface.DisableSpells =	ButtonGetPressedFlag( "DisableSpells" .. "Button" )			
	Interface.SaveBoolean( "DisableSpells", Interface.DisableSpells ) 
	
	Interface.ShowSpellName =	ButtonGetPressedFlag( "ShowSpellName" .. "Button" )			
	Interface.SaveBoolean( "ShowSpellName", Interface.ShowSpellName ) 
	
	Interface.noPoisonOthers =	ButtonGetPressedFlag( "noPoisonOthers" .. "Button" )			
	Interface.SaveBoolean( "noPoisonOthers", Interface.noPoisonOthers ) 
	
	
	if containerReload then
		SettingsWindow.DestroyContainers()
		if not Interface.GridLegacy then
			SettingsWindow.ResizeContainers()
		end
	end
	
	MobilesOnScreen.SaveFilterSettings()	
	StatusWindow.ToggleStrLabel()
	OverheadText.UpdateSettings()	
	-- push the new values to c++
	needsReload = UserSettingsChanged()
	
	if ( needsReload == true ) then
		InterfaceCore.ReloadUI()
	end
end

function SettingsWindow.ClearTempKeybindings()
	for key = 1, table.getn( SettingsWindow.Keybindings )do
		SettingsWindow.Keybindings[key].newValue = nil
	end
end

function SettingsWindow.OnResetButton()
	local okayButton = { textTid = UO_StandardDialog.TID_OKAY, callback = function()SettingsWindow.ClearTempKeybindings(); BroadcastEvent( SystemData.Events.RESET_SETTINGS_TO_DEFAULT ); end }
	local cancelButton = { textTid = UO_StandardDialog.TID_CANCEL }
	local ResetConfirmWindow = 
	{
		windowName = "SettingsWindow", 
		titleTid = 1078994, 
		bodyTid = 1078995, 
		buttons = { okayButton, cancelButton }
	}
			
	UO_StandardDialog.CreateDialog( ResetConfirmWindow )
end

function SettingsWindow.OnCancelButton()

	-- Reload the current settings
	SettingsWindow.ClearTempKeybindings()
	SettingsWindow.UpdateSettings()
	
	-- Close the window		
	ToggleWindowByName( "SettingsWindow", "", nil )
end

function SettingsWindow.OnResetUILocButton()	
	WindowUtils.ForceResetWindowPositions()	
end

function SettingsWindow.ClearTabStates()
	-- The pressed flag isn't being used for these tabs to decide color anymore
	ButtonSetPressedFlag( "SettingsWindowGraphicsTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowKeyBindingsTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowSoundTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowOptionsTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowLegacyTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowProfanityTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowMobilesOnScreenTabButton", false )	
	ButtonSetPressedFlag( "SettingsWindowHealthbarsTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowContainersTabButton", false )
	ButtonSetPressedFlag( "SettingsWindowOverheadTextTabButton", false )
	
	ButtonSetDisabledFlag( "SettingsWindowGraphicsTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowKeyBindingsTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowSoundTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowOptionsTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowLegacyTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowProfanityTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowMobilesOnScreenTabButton", false )	
	ButtonSetDisabledFlag( "SettingsWindowHealthbarsTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowContainersTabButton", false )
	ButtonSetDisabledFlag( "SettingsWindowOverheadTextTabButton", false )
	
	WindowSetShowing( "SettingsWindowGraphicsTabButtonTab", true )
	WindowSetShowing( "SettingsWindowKeyBindingsTabButtonTab", true )
	WindowSetShowing( "SettingsWindowSoundTabButtonTab", true )
	WindowSetShowing( "SettingsWindowOptionsTabButtonTab", true )
	WindowSetShowing( "SettingsWindowLegacyTabButtonTab", true )
	WindowSetShowing( "SettingsWindowProfanityTabButtonTab", true )
	WindowSetShowing( "SettingsWindowMobilesOnScreenTabButtonTab", true )	
	WindowSetShowing( "SettingsWindowHealthbarsTabButtonTab", true )
	WindowSetShowing( "SettingsWindowContainersTabButtonTab", true )
	WindowSetShowing( "SettingsWindowOverheadTextTabButtonTab", true )
	
	for index = 1, SettingsWindow.Modes.NUM_MODES do
		WindowSetShowing( SettingsWindow.Modes.windows[index], false )
	end	
end

function SettingsWindow.OpenGraphicsTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowGraphicsTabButton", true )
	WindowSetShowing( "SettingsWindowGraphicsTabButtonTab", false )
	WindowSetShowing( "SettingsGraphicsWindow", true )
end

function SettingsWindow.OpenKeyBindingsTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowKeyBindingsTabButton", true )
	WindowSetShowing( "SettingsWindowKeyBindingsTabButtonTab", false )
	WindowSetShowing( "SettingsKeyBindingsWindow", true )
	WindowSetShowing( "SettingsKeyDefaultWindow", true )
end

function SettingsWindow.OpenSoundTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowSoundTabButton", true )
	WindowSetShowing( "SettingsWindowSoundTabButtonTab", false )
	WindowSetShowing( "SettingsSoundWindow", true )
end

function SettingsWindow.OpenOptionsTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowOptionsTabButton", true )
	WindowSetShowing( "SettingsWindowOptionsTabButtonTab", false )
	WindowSetShowing( "SettingsOptionsWindow", true )
end

function SettingsWindow.OpenLegacyTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowLegacyTabButton", true )
	WindowSetShowing( "SettingsWindowLegacyTabButtonTab", false )
	WindowSetShowing( "SettingsLegacyWindow", true )
end

function SettingsWindow.OpenProfanityTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowProfanityTabButton", true )
	WindowSetShowing( "SettingsWindowProfanityTabButtonTab", false )
	WindowSetShowing( "SettingsProfanityWindow", true )
end

function SettingsWindow.OpenMobilesTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowMobilesOnScreenTabButton", true )
	WindowSetShowing( "SettingsWindowMobilesOnScreenTabButtonTab", false )
	WindowSetShowing( "SettingsMobilesOnScreen", true )
end

function SettingsWindow.OpenHealthbarsTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowHealthbarsTabButton", true )
	WindowSetShowing( "SettingsWindowHealthbarsTabButtonTab", false )
	WindowSetShowing( "HealthbarsSettingsWindow", true )
end

function SettingsWindow.OpenContainersTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowContainersTabButton", true )
	WindowSetShowing( "SettingsWindowContainersTabButtonTab", false )
	WindowSetShowing( "ContainersSettingsWindow", true )
end

function SettingsWindow.OpenOverheadTextTab()
	SettingsWindow.ClearTabStates()
	ButtonSetDisabledFlag( "SettingsWindowOverheadTextTabButton", true )
	WindowSetShowing( "SettingsWindowOverheadTextTabButtonTab", false )
	WindowSetShowing( "OverheadTextSettingsWindow", true )
end

function SettingsWindow.OnKeyPicked()
	for key = 1, table.getn( SettingsWindow.Keybindings )do
		if( SystemData.ActiveWindow.name == "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name )then
			SettingsWindow.CurKeyIndex = key
		elseif( SystemData.Settings.GameOptions.legacyTargeting == true and key >= SettingsWindow.NON_LEGACY_BINDING_MIN and key <= SettingsWindow.NON_LEGACY_BINDING_MAX ) then
			LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "Action", 255, 255, 255 )
			LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "ActionValue", 128, 128, 128 )
		else
			LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "Action", 255, 255, 255 )
			LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[key].name .. "ActionValue", 255, 255, 255 )
		end
	end
		
	if ( SystemData.Settings.GameOptions.legacyTargeting == false or
	( SystemData.Settings.GameOptions.legacyTargeting == true and ( SettingsWindow.CurKeyIndex < SettingsWindow.NON_LEGACY_BINDING_MIN or SettingsWindow.CurKeyIndex > SettingsWindow.NON_LEGACY_BINDING_MAX) ) ) then
		--Debug.PrintToDebugConsole( L"Active Window: ".. StringToWString( SystemData.ActiveWindow.name ) )
		LabelSetTextColor( SystemData.ActiveWindow.name .. "Action", 250, 250, 0 )
		LabelSetTextColor( SystemData.ActiveWindow.name .. "ActionValue", 250, 250, 0 )
		
		WindowClearAnchors( "AssignHotkeyInfo" )
		WindowAddAnchor( "AssignHotkeyInfo", "topleft", SystemData.ActiveWindow.name.."ActionValue", "bottomleft", 0, -6 )
		WindowSetShowing( "AssignHotkeyInfo", true )	
		
		SettingsWindow.RecordingKey = true
		
		SystemData.IsRecordingSettings = true
		BroadcastEvent( SystemData.Events.INTERFACE_RECORD_KEY )
	end
end

function SettingsWindow.KeyRecorded()	
	if( SettingsWindow.RecordingKey == true )then
		local keyIndex = SettingsWindow.CurKeyIndex
		
		WindowSetShowing( "AssignHotkeyInfo", false )
		
		LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[keyIndex].name .. "Action", 255, 255, 255 )
		LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[keyIndex].name .. "ActionValue", 255, 255, 255 )
	
		if( SystemData.RecordedKey ~= L"" )then
			for index = 1, table.getn( SettingsWindow.Keybindings )do
				if( SettingsWindow.Keybindings[keyIndex].type ~= nil )then
					local value = SystemData.Settings.Keybindings[SettingsWindow.Keybindings[index].type]
					if( SettingsWindow.Keybindings[index].newValue ~= nil )then
						value = SettingsWindow.Keybindings[index].newValue
					end
					
					if( value == SystemData.RecordedKey )then
						SystemData.BindingConflictItemIndex = index
						SystemData.BindingConflictType = SystemData.BindType.BINDTYPE_SETTINGS
						break
					end
				end
			end
		end
		
		if( SystemData.BindingConflictType ~= SystemData.BindType.BINDTYPE_NONE )then
			body = GetStringFromTid( SettingsWindow.TID_BINDING_CONFLICT_BODY )..L"\n\n"..HotbarSystem.GetKeyName(SystemData.BindingConflictHotbarId, SystemData.BindingConflictItemIndex, SystemData.BindingConflictType)..L"\n\n"..GetStringFromTid( SettingsWindow.TID_BINDING_CONFLICT_QUESTION )
			
			local yesButton = { textTid = SettingsWindow.TID_YES,
								callback =	function()
											HotbarSystem.ReplaceKey(
												SystemData.BindingConflictHotbarId, SystemData.BindingConflictItemIndex, SystemData.BindingConflictType,
												0, keyIndex, SystemData.BindType.BINDTYPE_SETTINGS,
												SystemData.RecordedKey, L"")
											end
							  }
			local noButton = { textTid = SettingsWindow.TID_NO }
			local windowData = 
			{
				windowName = "SettingsWindow", 
				titleTid = SettingsWindow.TID_BINDING_CONFLICT_TITLE, 
				body = body, 
				buttons = { yesButton, noButton }
			}
			UO_StandardDialog.CreateDialog( windowData )
		else	
			SettingsWindow.Keybindings[keyIndex].newValue = SystemData.RecordedKey
			SettingsWindow.UpdateKeyBindings()
			
			BroadcastEvent( SystemData.Events.KEYBINDINGS_UPDATED )
		end
		
		SystemData.IsRecordingSettings = false
		SettingsWindow.RecordingKey = false
	end
end

function SettingsWindow.KeyCancelRecord()
	if( SettingsWindow.RecordingKey == true )then
		WindowSetShowing( "AssignHotkeyInfo", false )
		
		local keyIndex = SettingsWindow.CurKeyIndex
		LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[keyIndex].name .. "Action", 255, 255, 255 )
		LabelSetTextColor( "SettingsKeyBindings"..SettingsWindow.Keybindings[keyIndex].name .. "ActionValue", 255, 255, 255 )
		
		SystemData.IsRecordingSettings = false
		SettingsWindow.RecordingKey = false
	end
end

function SettingsWindow.OnIgnoreListAddButton()
	StartIgnoreListAdd(SettingsWindow.IGNORE_LIST_ALL)

	--hide the settings window and main menu window so player can pick something on screen	
	WindowSetShowing( "SettingsWindow", false )
	WindowSetShowing( "MainMenuWindow", false )
end

function SettingsWindow.OnIgnoreConfListAddButton()
	StartIgnoreListAdd(SettingsWindow.IGNORE_LIST_CONF)

	--hide the settings window and main menu window so player can pick something on screen	
	WindowSetShowing( "SettingsWindow", false )
	WindowSetShowing( "MainMenuWindow", false )
end

function SettingsWindow.ProfanityListUpdated()
	--the player has picked something, show the main menu and settings window
--	WindowSetShowing( "MainMenuWindow", true )
	WindowSetShowing( "SettingsWindow", true )

	SettingsWindow.PopulateProfanityList()
end

function SettingsWindow.PopulateProfanityList()
	-- local previousListItem -- Is there a reason this isn't in here?

	-- don't show the bad words for now
	local b = false -- NOTE: Due to layout changes on this gump, the bad words list will need re-anchoring if you set it to display!
	if b then
		-- clear bad words
		for i = 1, SettingsWindow.PreviousBadWordCount do
			--Debug.PrintToDebugConsole( L"destroy BadWord"..i )
			--hide instead of destroy because destroyWindow dosen't actually destroy it, it just puts it into the destroy queue
			WindowSetShowing( "BadWord"..i, false )
		end
		
		-- list all bad words
		local first = true
		SettingsWindow.PreviousBadWordCount = WindowData.BadWordListCount
		for i = 1, WindowData.BadWordListCount do
			--Debug.PrintToDebugConsole( L"create BadWord"..i )
			CreateWindowFromTemplate( "BadWord"..i, "BadWord", "SettingsBadWordFilter" )
			WindowSetShowing( "BadWord"..i, true )
			LabelSetText( "BadWord"..i, L"- "..WindowData.BadWordList[i] )
			if( first )then
				first = false
				WindowAddAnchor( "BadWord"..i, "topleft", "SettingsBadWordFilter", "topleft", 80, 110 )
			else
				WindowAddAnchor( "BadWord"..i, "bottomleft", previousListItem, "topleft", 0, 0 )
			end
	
			previousListItem = "BadWord"..i
		end
	end
	
	-- clear ignore list
	for i = 1, SettingsWindow.PreviousIgnoreListCount do
		--Debug.PrintToDebugConsole( L"destroy IgnoreListItem"..i )
		--Debug.PrintToDebugConsole( LabelGetText( "IgnoreListItem"..i ) )
		DestroyWindow( "IgnoreListItem"..i)
	end

	-- list all player in the ignore list
	first = true
	for i = 1, WindowData.IgnoreListCount do
		--Debug.PrintToDebugConsole( L"create IgnoreListItem"..i )
		--Debug.PrintToDebugConsole( L""..WindowData.IgnoreIdList[i]..L" "..WindowData.IgnoreNameList[i] )
		CreateWindowFromTemplate( "IgnoreListItem"..i, "IgnoreListItem", "SettingsBadWordFilter" )
		
		WindowSetShowing( "IgnoreListItem"..i, true )
		LabelSetText( "IgnoreListItem"..i, L"- "..WindowData.IgnoreNameList[i] )
		if( first )then
			first = false
			WindowAddAnchor( "IgnoreListItem"..i, "bottomleft", "IgnoreListDeleteButton", "topleft", 0, 10 )
		else
			WindowAddAnchor( "IgnoreListItem"..i, "bottomleft", previousListItem, "topleft", 0, 0 )
		end

		previousListItem = "IgnoreListItem"..i
	end
	SettingsWindow.PreviousIgnoreListCount = WindowData.IgnoreListCount
	
	-- clear conf ignore list
	for i = 1, SettingsWindow.PreviousIgnoreConfListCount do
		--Debug.PrintToDebugConsole( L"destroy IgnoreConfListItem"..i )
		--Debug.PrintToDebugConsole( LabelGetText( "IgnoreConfListItem"..i ) )
		DestroyWindow( "IgnoreConfListItem"..i)
	end

	-- list all player in the ignore list
	first = true
	for i = 1, WindowData.IgnoreConfListCount do
		--Debug.PrintToDebugConsole( L"create IgnoreConfListItem"..i )
		--Debug.PrintToDebugConsole( L""..WindowData.IgnoreConfIdList[i]..L" "..WindowData.IgnoreConfNameList[i] )
		CreateWindowFromTemplate( "IgnoreConfListItem"..i, "IgnoreConfListItem", "SettingsBadWordFilter" )
		
		WindowSetShowing( "IgnoreConfListItem"..i, true )
		LabelSetText( "IgnoreConfListItem"..i, L"- "..WindowData.IgnoreConfNameList[i] )
		if( first )then
			first = false
			WindowAddAnchor( "IgnoreConfListItem"..i, "bottomleft", "IgnoreConfListDeleteButton", "topleft", 0, 10 )
		else
			WindowAddAnchor( "IgnoreConfListItem"..i, "bottomleft", previousListItem, "topleft", 0, 0 )
		end

		previousListItem = "IgnoreConfListItem"..i
	end
	SettingsWindow.PreviousIgnoreConfListCount = WindowData.IgnoreConfListCount

	ScrollWindowUpdateScrollRect( "SettingsProfanityWindow" )	
end

function SettingsWindow.OnIgnoreListDeleteButton()
	if SettingsWindow.CurIgnoreListIdx == -1 then
		return
	end

	local idx = SettingsWindow.CurIgnoreListIdx
	--Debug.PrintToDebugConsole( L"current idx "..idx )
	local id = WindowData.IgnoreIdList[idx]
	--Debug.PrintToDebugConsole( L"id at idx "..id )
	DeleteFromIgnoreList( id, SettingsWindow.IGNORE_LIST_ALL )
	SettingsWindow.CurIgnoreListIdx = -1
	SettingsWindow.PopulateProfanityList()
end

function SettingsWindow.OnIgnoreConfListDeleteButton()
	if SettingsWindow.CurIgnoreConfListIdx == -1 then
		return
	end

	local idx = SettingsWindow.CurIgnoreConfListIdx
	--Debug.PrintToDebugConsole( L"conf current idx "..idx )
	local id = WindowData.IgnoreConfIdList[idx]
	--Debug.PrintToDebugConsole( L"conf id at idx "..id )
	DeleteFromIgnoreList( id, SettingsWindow.IGNORE_LIST_CONF )
	SettingsWindow.CurIgnoreConfListIdx = -1
	SettingsWindow.PopulateProfanityList()
end

function SettingsWindow.OnIgnoreListChatListButton()
	SettingsWindow.ignoreListType = SettingsWindow.IGNORE_LIST_ALL
	CreateWindow("IgnoreWindow", true)
end

function SettingsWindow.OnIgnoreConfListChatListButton()
	SettingsWindow.ignoreListType = SettingsWindow.IGNORE_LIST_CONF
	CreateWindow("IgnoreWindow", true)
end

function SettingsWindow.OnIgnoreListItemClicked()
	for i = 1, WindowData.IgnoreListCount do
		LabelSetTextColor( "IgnoreListItem"..i, 255, 255, 255 )
		if( SystemData.ActiveWindow.name == "IgnoreListItem"..i )then
			SettingsWindow.CurIgnoreListIdx = i
		end
	end

	LabelSetTextColor( SystemData.ActiveWindow.name, 250, 250, 0 )
end

function SettingsWindow.OnIgnoreConfListItemClicked()
	for i = 1, WindowData.IgnoreConfListCount do
		LabelSetTextColor( "IgnoreConfListItem"..i, 255, 255, 255 )
		if( SystemData.ActiveWindow.name == "IgnoreConfListItem"..i )then
			SettingsWindow.CurIgnoreConfListIdx = i
		end
	end

	LabelSetTextColor( SystemData.ActiveWindow.name, 250, 250, 0 )
end

function SettingsWindow.UpdateGammaVal()
	local gamma = SliderBarGetCurrentPosition( "GammaSliderBar" )
	LabelSetText( "GammaVal", wstring.format( L"%2.2f", gamma ) )
	
	--Debug.Print("Framerate max: "..SystemData.Settings.Resolution.framerateMax)
end

function SettingsWindow.OnShowResetLegacyDialog()
	if( ButtonGetPressedFlag( "LegacyChatButton" )== true )then
		local yesButton = { textTid = SettingsWindow.TID_YES, callback = function()SettingsWindow.ResetLegacyKeyBindings()end }
		local noButton = { textTid = SettingsWindow.TID_NO }
		local windowData = 
		{
			windowName = "Root", 
			titleTid = SettingsWindow.TID_INFO, 
			bodyTid = SettingsWindow.TID_RESETLEGACYBINDINGS_CHAT, 
			buttons = { yesButton, noButton }
		}
		UO_StandardDialog.CreateDialog( windowData )	 
	end
end

function SettingsWindow.LegacyTargetingButtonOnLButtonUp()
	SettingsWindow.ResetScrollWheelOptions()
end

function SettingsWindow.LabelOnMouseOver()
	local windowName = SystemData.ActiveWindow.name
	local detailTID = WindowGetId(windowName)
	
	if ( (detailTID ~= nil) and (detailTID ~= 0) ) then
		local text = GetStringFromTid(detailTID)
		Tooltips.CreateTextOnlyTooltip(windowName, text)
		Tooltips.Finalize()
		Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
	end 
end

function SettingsWindow.Check()
	
	local win = string.gsub(SystemData.ActiveWindow.name, "Label", "Button")
	ButtonSetPressedFlag( win, not ButtonGetPressedFlag( win ))
	SettingsWindow.CheckEnable()
end

function SettingsWindow.CheckEnable()
end

function SettingsWindow.DestroyContainers()
	for id, value in pairs(ContainerWindow.OpenContainers) do
		DestroyWindow("ContainerWindow_"..id)
	end

	for cId, cValue in pairs(WindowData.ContainerWindow) do
		--Debug.Print("SettingsWindow.DestroyContainers: "..cId)
		UnregisterWindowData(WindowData.ContainerWindow.Type, cId)				
	end
end

function SettingsWindow.ResizeContainers()
	for id, value in pairs(ContainerWindow.OpenContainers) do
		ContainerWindow.LegacyGridDock("ContainerWindow_"..id)
	end
end

function SettingsWindow.PickColor()
	local color = SystemData.ActiveWindow.name
	color = string.gsub(color, "Button", "")
	SettingsWindow.HuePickerWindow = color
	
	color = string.gsub(color, "OverheadTextOptions", "")
	SettingsWindow.HuePickerWindowRequest = color
	local defaultColors = {
		0, --HUE_NONE 
		34, --HUE_RED
		53, --HUE_YELLOW
		63, --HUE_GREEN
		89, --HUE_BLUE
		119, --HUE_PURPLE
		144, --HUE_ORANGE
		368, --HUE_GREEN_2
		946, --HUE_GREY
		}
	local hueTable = {}
	for idx, hue in pairs(defaultColors) do
		for i=0,8 do
			hueTable[(idx-1)*10+i+1] = hue+i
		end
	end
	local Brightness = 1
	CreateWindowFromTemplate( "ColorPicker", "ColorPickerWindowTemplate", "Root" )
	WindowSetLayer( "ColorPicker", Window.Layers.SECONDARY	)
	ColorPickerWindow.SetNumColorsPerRow(9)
	ColorPickerWindow.SetSwatchSize(30)
	ColorPickerWindow.SetWindowPadding(4,4)
	ColorPickerWindow.SetFrameEnabled(true)
	ColorPickerWindow.SetCloseButtonEnabled(true)
	ColorPickerWindow.SetColorTable(hueTable,"ColorPicker")
	ColorPickerWindow.DrawColorTable("ColorPicker")
	ColorPickerWindow.SetAfterColorSelectionFunction(SettingsWindow.ColorPicked)
	local w, h = WindowGetDimensions("ColorPicker")
	WindowAddAnchor( "ColorPicker", "topleft", SettingsWindow.HuePickerWindow .. "Button", "topleft", 50, -h)
	ColorPickerWindow.SetFrameEnabled(false)
	WindowSetShowing( "ColorPicker", true )
	ColorPickerWindow.SelectColor("ColorPicker", 1)
end

function SettingsWindow.ColorPicked()
		local huePicked = ColorPickerWindow.colorSelected["ColorPicker"]

		if (SettingsWindow.HuePickerWindowRequest== "ContainerGridColor") then
			ContainerWindow.BaseGridColor.r,ContainerWindow.BaseGridColor.g,ContainerWindow.BaseGridColor.b,ContainerWindow.BaseGridColor.a = HueRGBAValue(huePicked)
			Interface.SaveColor("BaseGridColor", ContainerWindow.BaseGridColor)
			SettingsWindow.DestroyContainers()
			
		elseif (SettingsWindow.HuePickerWindowRequest== "ContainerGridAlternateColor") then
			ContainerWindow.AlternateBackpack.r,ContainerWindow.AlternateBackpack.g,ContainerWindow.AlternateBackpack.b,ContainerWindow.AlternateBackpack.a = HueRGBAValue(huePicked)
			Interface.SaveColor("AlternateBackpack", ContainerWindow.AlternateBackpack)
			SettingsWindow.DestroyContainers()
			
		elseif (SettingsWindow.HuePickerWindowRequest== "colorHeal") then
			TextParsing.Heal.r,TextParsing.Heal.g,TextParsing.Heal.b,TextParsing.Heal.a = HueRGBAValue(huePicked)
			Interface.SaveColor("TextParsingHeal", TextParsing.Heal)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorCurse") then
			TextParsing.Curse.r,TextParsing.Curse.g,TextParsing.Curse.b,TextParsing.Curse.a = HueRGBAValue(huePicked)
			Interface.SaveColor("TextParsingCurse", TextParsing.Curse)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorPara") then
			TextParsing.Paralyze.r,TextParsing.Paralyze.g,TextParsing.Paralyze.b,TextParsing.Paralyze.a = HueRGBAValue(huePicked)
			Interface.SaveColor("TextParsingParalyze", TextParsing.Paralyze)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorNeutral") then
			TextParsing.Neutral.r,TextParsing.Neutral.g,TextParsing.Neutral.b,TextParsing.Neutral.a = HueRGBAValue(huePicked)
			Interface.SaveColor("TextParsingNeutral", TextParsing.Neutral)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorNeg") then
			TextParsing.OverHeadError.r,TextParsing.OverHeadError.g,TextParsing.OverHeadError.b,TextParsing.OverHeadError.a = HueRGBAValue(huePicked)
			Interface.SaveColor("TextParsingOverHeadError", TextParsing.OverHeadError)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorPos") then
			TextParsing.SpecialColor.r,TextParsing.SpecialColor.g,TextParsing.SpecialColor.b,TextParsing.SpecialColor.a = HueRGBAValue(huePicked)
			Interface.SaveColor("TextParsingSpecialColor", TextParsing.SpecialColor)
			
		elseif (SettingsWindow.HuePickerWindowRequest== "colorYou") then
			DamageWindow.YOUGETAMAGE_COLOR.r,DamageWindow.YOUGETAMAGE_COLOR.g,DamageWindow.YOUGETAMAGE_COLOR.b,DamageWindow.YOUGETAMAGE_COLOR.a = HueRGBAValue(huePicked)
			Interface.SaveColor("DamageWindowYOUGETAMAGE_COLOR", DamageWindow.YOUGETAMAGE_COLOR)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorPet") then
			DamageWindow.PETGETDAMAGE_COLOR.r,DamageWindow.PETGETDAMAGE_COLOR.g,DamageWindow.PETGETDAMAGE_COLOR.b,DamageWindow.PETGETDAMAGE_COLOR.a = HueRGBAValue(huePicked)
			Interface.SaveColor("DamageWindowPETGETDAMAGE_COLOR", DamageWindow.PETGETDAMAGE_COLOR)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorEnemy") then
			DamageWindow.OTHERGETDAMAGE_COLOR.r,DamageWindow.OTHERGETDAMAGE_COLOR.g,DamageWindow.OTHERGETDAMAGE_COLOR.b,DamageWindow.OTHERGETDAMAGE_COLOR.a = HueRGBAValue(huePicked)
			Interface.SaveColor("DamageWindowOTHERGETDAMAGE_COLOR", DamageWindow.OTHERGETDAMAGE_COLOR)
		
		elseif (SettingsWindow.HuePickerWindowRequest== "colorPhys") then
			SpellsInfo.PHYSICAL.r,SpellsInfo.PHYSICAL.g,SpellsInfo.PHYSICAL.b,SpellsInfo.PHYSICAL.a  = HueRGBAValue(huePicked)
			Interface.SaveColor("SpellsInfoPHYSICAL", SpellsInfo.PHYSICAL)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorFire") then
			SpellsInfo.FIRE.r,SpellsInfo.FIRE.g,SpellsInfo.FIRE.b,SpellsInfo.FIRE.a = HueRGBAValue(huePicked)
			Interface.SaveColor("SpellsInfoFIRE", SpellsInfo.FIRE)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorCold") then
			SpellsInfo.COLD.r,SpellsInfo.COLD.g,SpellsInfo.COLD.b,SpellsInfo.COLD.a = HueRGBAValue(huePicked)
			Interface.SaveColor("SpellsInfoCOLD", SpellsInfo.COLD)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorPois") then
			SpellsInfo.POISON.r,SpellsInfo.POISON.g,SpellsInfo.POISON.b,SpellsInfo.POISON.a = HueRGBAValue(huePicked)
			Interface.SaveColor("SpellsInfoPOISON", SpellsInfo.POISON)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorEner") then
			SpellsInfo.ENERGY.r,SpellsInfo.ENERGY.g,SpellsInfo.ENERGY.b,SpellsInfo.ENERGY.a = HueRGBAValue(huePicked)
			Interface.SaveColor("SpellsInfoENERGY", SpellsInfo.ENERGY)
		elseif (SettingsWindow.HuePickerWindowRequest== "colorChaos") then
			SpellsInfo.Chaos.r,SpellsInfo.Chaos.g,SpellsInfo.Chaos.b,SpellsInfo.Chaos.a = HueRGBAValue(huePicked)
			Interface.SaveColor("SpellsInfoChaos", SpellsInfo.Chaos)
		end
		local r,g,b,a = HueRGBAValue(huePicked)
		WindowSetTintColor(SettingsWindow.HuePickerWindow .. "Button", r,g,b)
		
		SettingsWindow.HuePickerWindowRequest= ""
		SettingsWindow.HuePickerWindow = ""
		DestroyWindow("ColorPicker")
		
end

function SettingsWindow.IncreaseTextSize()
	OverheadText.OverhedTextSize =OverheadText.OverhedTextSize + 0.1
		
	if (OverheadText.OverhedTextSize > 1.5) then
		OverheadText.OverhedTextSize = 1.5
	end
	Interface.SaveNumber("OverhedTextSize", OverheadText.OverhedTextSize)
	WindowUtils.SendOverheadText(GetStringFromTid(1155472), 23  , false, false)
end

function SettingsWindow.DecreaseTextSize()
	OverheadText.OverhedTextSize =OverheadText.OverhedTextSize - 0.1
	if (OverheadText.OverhedTextSize < 0.5) then
		OverheadText.OverhedTextSize = 0.5
	end
	Interface.SaveNumber("OverhedTextSize", OverheadText.OverhedTextSize)
	WindowUtils.SendOverheadText(GetStringFromTid(1155472), 23 , false, false)
end

function SettingsWindow.ChatFont()
	FontSelector.Selection = "chat"
	if (not DoesWindowNameExist("FontSelector")) then
		CreateWindow("FontSelector", true)
	else
		WindowSetShowing("FontSelector", true)
	end
	
	FontSelector.OnShown()
	WindowSetShowing(FontSelector.RunicFontItem, false)
	WindowUtils.SetWindowTitle("FontSelector", GetStringFromTid(1155347))
end

function SettingsWindow.NamesFont()
	FontSelector.Selection = "names"
	if (not DoesWindowNameExist("FontSelector")) then
		CreateWindow("FontSelector", true)
	else
		WindowSetShowing("FontSelector", true)
	end
	FontSelector.OnShown()
	WindowSetShowing(FontSelector.RunicFontItem, false)
	WindowUtils.SetWindowTitle("FontSelector", GetStringFromTid(1155348))
end

function SettingsWindow.SpellFont()
	FontSelector.Selection = "spells"
	if (not DoesWindowNameExist("FontSelector")) then
		CreateWindow("FontSelector", true)
	else
		WindowSetShowing("FontSelector", true)
	end
	FontSelector.OnShown()
	WindowSetShowing(FontSelector.RunicFontItem, not Interface.ShowSpellName)
	WindowUtils.SetWindowTitle("FontSelector", GetStringFromTid(1155349))
end

function SettingsWindow.DamageFont()
	FontSelector.Selection = "damage"
	if (not DoesWindowNameExist("FontSelector")) then
		CreateWindow("FontSelector", true)
	else
		WindowSetShowing("FontSelector", true)
	end
	FontSelector.OnShown()
	WindowSetShowing(FontSelector.RunicFontItem, false)
	WindowUtils.SetWindowTitle("FontSelector", GetStringFromTid(1155350))
end