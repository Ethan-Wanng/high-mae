#!/usr/bin/env ruby
# frozen_string_literal: true

require 'xcodeproj'

root = File.expand_path('..', __dir__)
project_path = File.join(root, 'flutter_ui', 'ios', 'Runner.xcodeproj')
project = Xcodeproj::Project.open(project_path)
runner = project.targets.find { |target| target.name == 'Runner' }
abort 'Runner target not found' unless runner

runner.build_configurations.each do |config|
  config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = ENV.fetch('IOS_BUNDLE_ID', 'com.highmae.wing')
  config.build_settings['CODE_SIGN_ENTITLEMENTS'] = 'Runner/Runner.entitlements'
  config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '15.0'
end

extension = project.targets.find { |target| target.name == 'PacketTunnel' }
unless extension
  extension = project.new_target(
    :app_extension,
    'PacketTunnel',
    :ios,
    '15.0',
    nil,
    :swift
  )
  group = project.main_group.find_subpath('PacketTunnel', true)
  group.set_source_tree('<group>')
  provider = group.new_file('PacketTunnelProvider.swift')
  extension.source_build_phase.add_file_reference(provider)

  extension.build_configurations.each do |config|
    config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = "#{ENV.fetch('IOS_BUNDLE_ID', 'com.highmae.wing')}.PacketTunnel"
    config.build_settings['INFOPLIST_FILE'] = 'PacketTunnel/Info.plist'
    config.build_settings['CODE_SIGN_ENTITLEMENTS'] = 'PacketTunnel/PacketTunnel.entitlements'
    config.build_settings['SWIFT_VERSION'] = '5.0'
    config.build_settings['SKIP_INSTALL'] = 'YES'
    config.build_settings['APPLICATION_EXTENSION_API_ONLY'] = 'YES'
    config.build_settings['MARKETING_VERSION'] = ENV.fetch('FLUTTER_BUILD_NAME', '1.0.6')
    config.build_settings['CURRENT_PROJECT_VERSION'] = ENV.fetch('FLUTTER_BUILD_NUMBER', '10062')
  end

  runner.add_dependency(extension)
  embed = runner.copy_files_build_phases.find { |phase| phase.name == 'Embed App Extensions' }
  embed ||= runner.new_copy_files_build_phase('Embed App Extensions')
  embed.dst_subfolder_spec = '13'
  embed.add_file_reference(extension.product_reference, true)
end

framework_group = project.main_group.find_subpath('Frameworks', true)
framework_group.set_source_tree('<group>')
core = framework_group.files.find { |file| file.path == 'WingCore.xcframework' }
core ||= framework_group.new_file('WingCore.xcframework')
[runner, extension].each do |target|
  unless target.frameworks_build_phase.files_references.include?(core)
    target.frameworks_build_phase.add_file_reference(core)
  end
end

project.save
puts 'Configured native PacketTunnel target.'
