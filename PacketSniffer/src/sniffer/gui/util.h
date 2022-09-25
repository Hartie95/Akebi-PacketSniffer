#pragma once
#include <string>

#include <sniffer/Profiler.h>
#include <sniffer/script/ScriptSelector.h>
#include <fmt/format.h>
#include <cheat-base/render/gui-util.h>

#include <imgui.h>

#include <filesystem>
#include <fstream>
#include <sniffer/packet/PacketManager.h>

// for open directory dialog
#include <ShlObj_core.h>
#include <atlbase.h>


namespace fs = std::filesystem;
namespace sniffer::gui
{
	struct ComInit
	{
		ComInit() { CoInitialize(nullptr); }
		~ComInit() { CoUninitialize(); }
	};
	
	class Session
	{
	public:
		Session() {};
		~Session() {};

		static int showFolderSelect(wchar_t* result) {
			ComInit com;
			CComPtr<IFileOpenDialog> pFolderDlg;
			pFolderDlg.CoCreateInstance(CLSID_FileOpenDialog);

			FILEOPENDIALOGOPTIONS opt{};
			pFolderDlg->GetOptions(&opt);
			pFolderDlg->SetOptions(opt | FOS_PICKFOLDERS | FOS_PATHMUSTEXIST);

			if (!SUCCEEDED(pFolderDlg->Show(nullptr))) {
				return 1;
			}

			CComPtr<IShellItem> pSelectedItem;
			pFolderDlg->GetResult(&pSelectedItem);
			CComHeapPtr<wchar_t> pPath;
			pSelectedItem->GetDisplayName(SIGDN_FILESYSPATH, &pPath);
			wcscpy(result, pPath.m_pData);
			return 0;
		}

		static void dump(void)
		{
			wchar_t pathArray[255] = { 0 };
			if (!SUCCEEDED(showFolderSelect(pathArray))) {
				return;
			}


			const auto& packets = sniffer::packet::PacketManager::GetPackets();

			fs::path path(pathArray);
			int count = 0;

			// packet, packetView
			for (const auto& packet : packets) {

				auto file_name = std::to_string(++count);

				std::fstream file(path.string() + '/' + file_name + ".json", std::ios::out | std::ios::binary);

				if (file.is_open()) {
					nlohmann::json j;
					packet.to_json(j);

					file << j;
				}
				file.close();
			}

			return;
		}
		
		static void load(void)
		{

			wchar_t pathArray[255] = { 0 };
			if (!SUCCEEDED(showFolderSelect(pathArray))) {
				return;
			}

			fs::path path(pathArray);
			fs::path jsonExtension(".json");

			std::error_code ec;

			for (const auto& entry : fs::directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
				if (ec) {
					// print error
					continue;
				}

				if (fs::is_regular_file(entry) && entry.path().extension().compare(jsonExtension) == 0) {
					std::fstream file(entry.path());

					auto j = nlohmann::json::parse(file);

					sniffer::packet::Packet packet;
					packet.from_json(j);

					sniffer::packet::PacketManager::s_ReceiveQueue.push(packet.raw());
					file.close();
				}
			}
		}
	};

	void DrawScriptSelector(script::ScriptSelector* selector);
	

	template<class T>
	void DrawProfiler(const std::string& title, Profiler<T>& profiler, float width = 0)
	{
		auto& currentProfile = profiler.current();
		auto& currentProfileName = profiler.current_name();
		if (width != 0)
			ImGui::PushItemWidth(width);

		if (ImGui::BeginCombo(title.c_str(), currentProfileName.c_str())) // The second parameter is the label previewed before opening the combo.
		{
			for (auto& [name, element] : profiler.profiles())
			{
				bool is_selected = (&currentProfile == &element);
				if (ImGui::Selectable(name.c_str(), is_selected))
					profiler.switch_profile(name);
				if (is_selected)
					ImGui::SetItemDefaultFocus();
			}
			ImGui::EndCombo();
		}

		if (width != 0)
			ImGui::PopItemWidth();

		ImGui::SameLine();
		
		ImGui::PushID(title.c_str());

		bool isOpen = ImGui::IsPopupOpen("Profilers");
		if (isOpen)
			ImGui::BeginDisabled();

		if (ImGui::Button("Configure"))
			ImGui::OpenPopup("Profilers");

		if (isOpen)
			ImGui::EndDisabled();

		if (ImGui::BeginPopup("Profilers"))
		{
			static ImGuiTableFlags flags =
				ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable
				| ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV | ImGuiTableFlags_NoBordersInBody
				| ImGuiTableFlags_ScrollY;
			if (ImGui::BeginTable("ProfileTable", 2, flags,
				ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing() * 10), 0.0f))
			{
				ImGui::TableSetupColumn("Name");
				ImGui::TableSetupColumn("Actions");
				ImGui::TableSetupScrollFreeze(0, 1);
				ImGui::TableHeadersRow();

				static std::string tempName = "";
				static const std::string* renameName = nullptr;
				const std::string* removeName = nullptr;
				for (auto& [name, element] : profiler.profiles())
				{
					ImGui::TableNextRow();
					ImGui::TableNextColumn();

					ImGui::PushID(&element);

					ImGui::Text(name.c_str());

					ImGui::TableNextColumn();

					if (ImGui::Button("Remove"))
						removeName = &name;
					
					ImGui::SameLine();

					if (ImGui::Button("Rename"))
					{
						tempName = name;
						renameName = &name;
						ImGui::OpenRenamePopup(tempName);
					}
					
					ImGui::PopID();
				}

				ImGui::EndTable();

				std::string newName;
				if (ImGui::DrawRenamePopup(newName))
				{
					profiler.rename_profile(*renameName, newName);
					renameName = nullptr;
				}

				if (removeName != nullptr)
				{
					profiler.remove_profile(*removeName);
					removeName = nullptr;
				}
			}

			if (ImGui::Button("Add new profile"))
			{
				size_t index = 0;
				std::string name{};
				do
				{
					index++;
					name = fmt::format("Profile #{}", index);

				} while (profiler.has_profile(name));

				profiler.add_profile(name, T());
			}

			ImGui::EndPopup();
		}

		ImGui::PopID();
	}
}