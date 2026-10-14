# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # Sign-in page design: the instance design, previews, uploaded images and the catalog.
    #
    # A design is a Hash with these sections (all optional; keys are camelCase,
    # as sent). Unknown keys are refused with their path.
    #
    #   version     1
    #   preset      "minimal" | "atlas" | "glass" | "midnight" | "editorial" | "terminal" |
    #               "sunrise" | "forest" | "grape" | "slate" | "split-photo" | "bold"
    #   colorScheme "auto" | "light" | "dark"
    #   palette, paletteDark  { primary, primaryInk, accent, background, surface, text, muted,
    #                           border, danger, success, inputBackground, inputText }  ("#rrggbb")
    #   typography  { font, headingFont, baseSize (12-20), headingWeight, bodyWeight,
    #                 letterCase ("none" | "uppercase"), scale }
    #   shape       { radius (0-32), controlRadius (0-999), borderWidth (0-3) }
    #   elevation   { cardShadow: "none" | "sm" | "md" | "lg" | "xl" }
    #   spacing     { density: "compact" | "comfortable" | "spacious" }
    #   card        { style: "solid" | "glass" | "outline" | "none", blur (0-40), width: "narrow" | "normal" | "wide" }
    #   layout      { position: "center" | "left" | "right" | "split", splitImageSide: "left" | "right",
    #                 logoPlacement: "card" | "page" | "hidden", logoSize: "sm" | "md" | "lg" }
    #   buttons     { style: "solid" | "outline" | "soft" | "gradient", socialLayout: "list" | "grid" | "icons" }
    #   inputs      { style: "outline" | "filled" | "underline" }
    #   background, backgroundDark
    #               { color, gradient: { type: "linear" | "radial", angle, stops: [{ color, at }] },
    #                 image: { assetId, fit, position, overlay: { color, opacity }, blur },
    #                 pattern: "none" | "dots" | "grid" | "noise" }
    #   logo        { assetId, darkAssetId }
    #
    # {SECTIONS} lists the top-level keys. Image ids come from {#upload_asset}.
    #
    #   asset = atlas.design.upload_asset(File.binread("hero.jpg"), kind: "background")
    #   atlas.design.update(preset: "glass", background: { image: { assetId: asset["asset_id"] } })
    class Design < Base
      # The top-level design sections.
      SECTIONS = %w[
        version preset colorScheme palette paletteDark typography shape elevation spacing
        card layout buttons inputs background backgroundDark logo
      ].freeze

      # +GET /v1/instance/design+ — the instance's sign-in page design: stored overrides, resolved design, contrast warnings.
      def get
        request(method: :get, path: "/v1/instance/design")
      end

      # +PUT /v1/instance/design+ — replace the instance design.
      def replace(design)
        request(method: :put, path: "/v1/instance/design", body: { design: design })
      end

      # +PATCH /v1/instance/design+ — change part of the instance design: nested settings merge, nil removes a setting.
      def update(design)
        request(method: :patch, path: "/v1/instance/design", body: { design: design })
      end

      # +POST /v1/instance/design/preview+ — compile an unsaved design (CSS variables, data attributes, fonts, warnings, rendered page). Nothing is saved.
      def preview(design)
        request(method: :post, path: "/v1/instance/design/preview", body: { design: design })
      end

      # +GET /v1/design/assets+ — this instance's uploaded design images, newest first.
      def list_assets
        request(method: :get, path: "/v1/design/assets")
      end

      # +DELETE /v1/design/assets/:id+ — delete a design image. Refused with 409 while a saved design still uses it.
      def delete_asset(asset_id)
        request(method: :delete, path: "/v1/design/assets/#{enc(asset_id)}")
      end

      # +GET /v1/design/catalog+ — the design catalog: presets, curated fonts and the CSS variable set.
      def catalog
        request(method: :get, path: "/v1/design/catalog")
      end

      # +POST /v1/design/assets+ — upload a design image (a background or a
      # logo): raw PNG, JPEG, GIF or WebP bytes, up to 8 MB. The content type
      # is detected from the bytes unless given. Use the returned +asset_id+ in
      # a design (+logo.assetId+, +background.image.assetId+).
      #
      #   asset = atlas.design.upload_asset(File.binread("bg.jpg"), kind: "background")
      def upload_asset(data, kind: nil, content_type: nil)
        upload_image("/v1/design/assets", data, content_type, kind)
      end
    end
  end
end
