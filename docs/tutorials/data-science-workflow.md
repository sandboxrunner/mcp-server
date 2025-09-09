# Data Science Workflow Tutorial

Learn how to use SandboxRunner for data science workflows with Python, pandas, numpy, and visualization libraries.

## Prerequisites

- SandboxRunner installed and configured (see [Getting Started Guide](../getting-started.md))
- Basic knowledge of Python and data science libraries
- Sample dataset (we'll create one in this tutorial)

## Overview

In this tutorial, you'll learn to:
1. Set up a Python environment with data science packages
2. Load and explore datasets
3. Perform data cleaning and transformation
4. Create visualizations
5. Run statistical analysis
6. Export results and plots

## Step 1: Create a Data Science Sandbox

First, create a sandbox with Python and data science tools:

```bash
curl -X POST http://localhost:8080/mcp/tools/create_sandbox \
  -H "Content-Type: application/json" \
  -d '{
    "image": "python:3.11-slim",
    "memory_limit": "2G",
    "cpu_limit": "2.0",
    "workspace_dir": "/workspace/datascience"
  }'
```

**Save the sandbox_id returned in the response for all subsequent steps.**

## Step 2: Install Required Packages

Install essential data science libraries:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "import sys\nprint(f\"Python version: {sys.version}\")\nprint(\"Installing packages...\")",
    "packages": [
      "pandas>=2.0.0",
      "numpy>=1.24.0", 
      "matplotlib>=3.6.0",
      "seaborn>=0.12.0",
      "scikit-learn>=1.3.0",
      "jupyter>=1.0.0",
      "plotly>=5.15.0"
    ]
  }'
```

## Step 3: Create Sample Dataset

Generate a realistic sales dataset for analysis:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "import pandas as pd\nimport numpy as np\nfrom datetime import datetime, timedelta\nimport random\n\n# Set seed for reproducibility\nnp.random.seed(42)\nrandom.seed(42)\n\n# Generate sales data\nstart_date = datetime(2023, 1, 1)\nend_date = datetime(2023, 12, 31)\ndate_range = pd.date_range(start=start_date, end=end_date, freq=\"D\")\n\n# Product categories and names\ncategories = [\"Electronics\", \"Clothing\", \"Home & Garden\", \"Sports\", \"Books\"]\nproducts = {\n    \"Electronics\": [\"Laptop\", \"Smartphone\", \"Tablet\", \"Headphones\", \"Camera\"],\n    \"Clothing\": [\"T-Shirt\", \"Jeans\", \"Jacket\", \"Sneakers\", \"Dress\"],\n    \"Home & Garden\": [\"Chair\", \"Table\", \"Lamp\", \"Plant\", \"Toolset\"],\n    \"Sports\": [\"Basketball\", \"Tennis Racket\", \"Yoga Mat\", \"Dumbbells\", \"Running Shoes\"],\n    \"Books\": [\"Fiction Novel\", \"Cookbook\", \"Biography\", \"Technical Manual\", \"Children Book\"]\n}\n\n# Generate sales records\nsales_data = []\nfor date in date_range:\n    # Number of sales per day (higher on weekends)\n    num_sales = np.random.poisson(50 if date.weekday() < 5 else 75)\n    \n    for _ in range(num_sales):\n        category = np.random.choice(categories, p=[0.3, 0.2, 0.2, 0.15, 0.15])\n        product = np.random.choice(products[category])\n        \n        # Price based on category\n        if category == \"Electronics\":\n            price = np.random.normal(500, 200)\n        elif category == \"Clothing\":\n            price = np.random.normal(50, 15)\n        elif category == \"Home & Garden\":\n            price = np.random.normal(150, 50)\n        elif category == \"Sports\":\n            price = np.random.normal(75, 25)\n        else:  # Books\n            price = np.random.normal(20, 5)\n        \n        price = max(5, price)  # Minimum price\n        quantity = np.random.poisson(2) + 1  # At least 1 item\n        \n        # Customer demographics\n        age_groups = [\"18-25\", \"26-35\", \"36-45\", \"46-55\", \"56+\"]\n        age_group = np.random.choice(age_groups)\n        \n        regions = [\"North\", \"South\", \"East\", \"West\", \"Central\"]\n        region = np.random.choice(regions)\n        \n        sales_data.append({\n            \"date\": date,\n            \"category\": category,\n            \"product\": product,\n            \"price\": round(price, 2),\n            \"quantity\": quantity,\n            \"revenue\": round(price * quantity, 2),\n            \"age_group\": age_group,\n            \"region\": region\n        })\n\n# Create DataFrame\ndf = pd.DataFrame(sales_data)\n\n# Add some missing values for data cleaning exercise\nmissing_indices = np.random.choice(df.index, size=int(0.02 * len(df)), replace=False)\ndf.loc[missing_indices, \"age_group\"] = None\n\nprint(f\"Generated dataset with {len(df):,} sales records\")\nprint(f\"Date range: {df[\"date\"].min()} to {df[\"date\"].max()}\")\nprint(f\"\\nDataset shape: {df.shape}\")\nprint(f\"\\nColumns: {list(df.columns)}\")\n\n# Save to CSV\ndf.to_csv(\"/workspace/sales_data.csv\", index=False)\nprint(\"\\nDataset saved to /workspace/sales_data.csv\")"
  }'
```

## Step 4: Explore the Dataset

Perform initial data exploration:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID", 
    "code": "# Load and explore the dataset\nimport pandas as pd\nimport numpy as np\n\n# Read the data\ndf = pd.read_csv(\"/workspace/sales_data.csv\")\ndf[\"date\"] = pd.to_datetime(df[\"date\"])\n\nprint(\"=== DATASET OVERVIEW ===\")\nprint(f\"Shape: {df.shape}\")\nprint(f\"\\nData types:\")\nprint(df.dtypes)\n\nprint(\"\\n=== FIRST 5 ROWS ===\")\nprint(df.head())\n\nprint(\"\\n=== BASIC STATISTICS ===\")\nprint(df.describe())\n\nprint(\"\\n=== MISSING VALUES ===\")\nprint(df.isnull().sum())\n\nprint(\"\\n=== UNIQUE VALUES PER COLUMN ===\")\nfor col in df.columns:\n    if col != \"date\":\n        unique_count = df[col].nunique()\n        if unique_count <= 10:\n            print(f\"{col}: {unique_count} unique values - {list(df[col].unique())[:5]}...\")\n        else:\n            print(f\"{col}: {unique_count} unique values\")\n\nprint(\"\\n=== REVENUE SUMMARY ===\")\ntotal_revenue = df[\"revenue\"].sum()\navg_order_value = df[\"revenue\"].mean()\nprint(f\"Total Revenue: ${total_revenue:,.2f}\")\nprint(f\"Average Order Value: ${avg_order_value:.2f}\")\nprint(f\"Total Orders: {len(df):,}\")\n\nprint(\"\\n=== CATEGORY BREAKDOWN ===\")\ncategory_stats = df.groupby(\"category\").agg({\n    \"revenue\": [\"sum\", \"mean\", \"count\"],\n    \"quantity\": \"sum\"\n}).round(2)\nprint(category_stats)"
  }'
```

## Step 5: Data Cleaning and Transformation

Clean the dataset and create new features:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "# Data cleaning and feature engineering\nimport pandas as pd\nimport numpy as np\nfrom datetime import datetime\n\n# Read data\ndf = pd.read_csv(\"/workspace/sales_data.csv\")\ndf[\"date\"] = pd.to_datetime(df[\"date\"])\n\nprint(\"=== DATA CLEANING ===\")\nprint(f\"Before cleaning: {df.shape[0]:,} rows\")\nprint(f\"Missing age_group values: {df[\"age_group\"].isnull().sum()}\")\n\n# Fill missing age groups with most common value\nmost_common_age = df[\"age_group\"].mode()[0]\ndf[\"age_group\"].fillna(most_common_age, inplace=True)\nprint(f\"Filled missing age_group values with: {most_common_age}\")\n\n# Remove any outliers (revenue > 3 standard deviations)\nrevenue_mean = df[\"revenue\"].mean()\nrevenue_std = df[\"revenue\"].std()\noutlier_threshold = revenue_mean + 3 * revenue_std\n\nbefore_outlier_removal = len(df)\ndf = df[df[\"revenue\"] <= outlier_threshold]\nprint(f\"Removed {before_outlier_removal - len(df)} outlier records\")\n\nprint(f\"After cleaning: {df.shape[0]:,} rows\")\n\nprint(\"\\n=== FEATURE ENGINEERING ===\")\n\n# Add time-based features\ndf[\"year\"] = df[\"date\"].dt.year\ndf[\"month\"] = df[\"date\"].dt.month\ndf[\"day_of_week\"] = df[\"date\"].dt.dayofweek\ndf[\"quarter\"] = df[\"date\"].dt.quarter\ndf[\"week_of_year\"] = df[\"date\"].dt.isocalendar().week\ndf[\"is_weekend\"] = df[\"day_of_week\"].isin([5, 6])\n\n# Add day names for better readability\nday_names = [\"Monday\", \"Tuesday\", \"Wednesday\", \"Thursday\", \"Friday\", \"Saturday\", \"Sunday\"]\ndf[\"day_name\"] = df[\"day_of_week\"].map(lambda x: day_names[x])\n\n# Season mapping\ndef get_season(month):\n    if month in [12, 1, 2]:\n        return \"Winter\"\n    elif month in [3, 4, 5]:\n        return \"Spring\"\n    elif month in [6, 7, 8]:\n        return \"Summer\"\n    else:\n        return \"Fall\"\n\ndf[\"season\"] = df[\"month\"].map(get_season)\n\n# Price categories\ndf[\"price_category\"] = pd.cut(df[\"price\"], \n                               bins=[0, 25, 50, 100, 500, float(\"inf\")],\n                               labels=[\"Budget\", \"Economy\", \"Mid-range\", \"Premium\", \"Luxury\"])\n\n# Revenue per item\ndf[\"revenue_per_item\"] = df[\"revenue\"] / df[\"quantity\"]\n\nprint(\"Added features:\")\nprint(\"- Time features: year, month, day_of_week, quarter, week_of_year, is_weekend, day_name, season\")\nprint(\"- Price categories: Budget, Economy, Mid-range, Premium, Luxury\")\nprint(\"- Revenue per item\")\n\n# Save cleaned data\ndf.to_csv(\"/workspace/sales_data_cleaned.csv\", index=False)\nprint(f\"\\nCleaned dataset saved to /workspace/sales_data_cleaned.csv\")\nprint(f\"Final shape: {df.shape}\")\n\n# Show sample of new features\nprint(\"\\n=== SAMPLE WITH NEW FEATURES ===\")\nprint(df[[\"date\", \"category\", \"revenue\", \"month\", \"day_name\", \"season\", \"price_category\", \"is_weekend\"]].head(10))"
  }'
```

## Step 6: Statistical Analysis

Perform comprehensive statistical analysis:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "# Statistical Analysis\nimport pandas as pd\nimport numpy as np\nfrom scipy import stats\nimport warnings\nwarnings.filterwarnings(\"ignore\")\n\n# Load cleaned data\ndf = pd.read_csv(\"/workspace/sales_data_cleaned.csv\")\ndf[\"date\"] = pd.to_datetime(df[\"date\"])\ndf[\"is_weekend\"] = df[\"is_weekend\"].astype(bool)\n\nprint(\"=== REVENUE ANALYSIS ===\")\n\n# Overall statistics\nprint(f\"Total Revenue: ${df[\"revenue\"].sum():,.2f}\")\nprint(f\"Average Daily Revenue: ${df.groupby(\"date\")[\"revenue\"].sum().mean():,.2f}\")\nprint(f\"Median Order Value: ${df[\"revenue\"].median():.2f}\")\nprint(f\"Standard Deviation: ${df[\"revenue\"].std():.2f}\")\n\nprint(\"\\n=== SEASONAL ANALYSIS ===\")\nseasonal_revenue = df.groupby(\"season\")[\"revenue\"].agg([\"sum\", \"mean\", \"count\"]).round(2)\nseasonal_revenue[\"avg_daily\"] = df.groupby([\"season\", \"date\"])[\"revenue\"].sum().groupby(\"season\").mean().round(2)\nprint(seasonal_revenue)\n\nprint(\"\\n=== CATEGORY PERFORMANCE ===\")\ncategory_stats = df.groupby(\"category\").agg({\n    \"revenue\": [\"sum\", \"mean\", \"count\"],\n    \"quantity\": \"sum\",\n    \"price\": \"mean\"\n}).round(2)\ncategory_stats.columns = [\"Total_Revenue\", \"Avg_Order_Value\", \"Order_Count\", \"Total_Quantity\", \"Avg_Price\"]\ncategory_stats[\"Revenue_Share\"] = (category_stats[\"Total_Revenue\"] / category_stats[\"Total_Revenue\"].sum() * 100).round(1)\nprint(category_stats)\n\nprint(\"\\n=== DAY OF WEEK ANALYSIS ===\")\nweekday_stats = df.groupby([\"day_name\", \"is_weekend\"]).agg({\n    \"revenue\": [\"sum\", \"mean\", \"count\"]\n}).round(2)\nprint(weekday_stats)\n\nprint(\"\\n=== REGIONAL ANALYSIS ===\")\nregional_stats = df.groupby(\"region\").agg({\n    \"revenue\": [\"sum\", \"mean\", \"count\"],\n    \"quantity\": \"sum\"\n}).round(2)\nregional_stats.columns = [\"Total_Revenue\", \"Avg_Order_Value\", \"Order_Count\", \"Total_Quantity\"]\nregional_stats[\"Market_Share\"] = (regional_stats[\"Total_Revenue\"] / regional_stats[\"Total_Revenue\"].sum() * 100).round(1)\nprint(regional_stats)\n\nprint(\"\\n=== AGE GROUP ANALYSIS ===\")\nage_stats = df.groupby(\"age_group\").agg({\n    \"revenue\": [\"sum\", \"mean\", \"count\"],\n    \"price\": \"mean\"\n}).round(2)\nage_stats.columns = [\"Total_Revenue\", \"Avg_Order_Value\", \"Order_Count\", \"Avg_Price\"]\nprint(age_stats)\n\nprint(\"\\n=== STATISTICAL TESTS ===\")\n\n# Test if weekend sales are significantly different from weekday sales\nweekend_revenue = df[df[\"is_weekend\"] == True][\"revenue\"]\nweekday_revenue = df[df[\"is_weekend\"] == False][\"revenue\"]\n\nt_stat, p_value = stats.ttest_ind(weekend_revenue, weekday_revenue)\nprint(f\"Weekend vs Weekday Revenue T-test:\")\nprint(f\"  T-statistic: {t_stat:.4f}\")\nprint(f\"  P-value: {p_value:.4f}\")\nprint(f\"  Significant difference: {\"Yes\" if p_value < 0.05 else \"No\"}\")\nprint(f\"  Weekend avg: ${weekend_revenue.mean():.2f}\")\nprint(f\"  Weekday avg: ${weekday_revenue.mean():.2f}\")\n\n# ANOVA test for categories\ncategory_groups = [group[\"revenue\"].values for name, group in df.groupby(\"category\")]\nf_stat, p_value_anova = stats.f_oneway(*category_groups)\nprint(f\"\\nCategory Revenue ANOVA:\")\nprint(f\"  F-statistic: {f_stat:.4f}\")\nprint(f\"  P-value: {p_value_anova:.4f}\")\nprint(f\"  Significant difference between categories: {\"Yes\" if p_value_anova < 0.05 else \"No\"}\")\n\n# Correlation analysis\nprint(\"\\n=== CORRELATION ANALYSIS ===\")\nnumeric_cols = [\"price\", \"quantity\", \"revenue\", \"month\", \"day_of_week\"]\ncorr_matrix = df[numeric_cols].corr().round(3)\nprint(corr_matrix)\n\nprint(\"\\n=== KEY INSIGHTS ===\")\n# Generate insights\nbest_season = seasonal_revenue[\"sum\"].idxmax()\nbest_category = category_stats[\"Total_Revenue\"].idxmax()\nbest_region = regional_stats[\"Total_Revenue\"].idxmax()\nbest_age_group = age_stats[\"Total_Revenue\"].idxmax()\n\nprint(f\"• Highest revenue season: {best_season}\")\nprint(f\"• Top performing category: {best_category}\")\nprint(f\"• Leading region: {best_region}\")\nprint(f\"• Most valuable age group: {best_age_group}\")\nprint(f\"• Weekend effect: {\"Higher\" if weekend_revenue.mean() > weekday_revenue.mean() else \"Lower\"} revenue than weekdays\")\n\n# Save analysis results\nanalysis_summary = {\n    \"total_revenue\": df[\"revenue\"].sum(),\n    \"total_orders\": len(df),\n    \"avg_order_value\": df[\"revenue\"].mean(),\n    \"best_season\": best_season,\n    \"best_category\": best_category,\n    \"best_region\": best_region,\n    \"weekend_vs_weekday_significant\": p_value < 0.05\n}\n\nimport json\nwith open(\"/workspace/analysis_summary.json\", \"w\") as f:\n    json.dump(analysis_summary, f, indent=2, default=str)\n\nprint(\"\\nAnalysis summary saved to /workspace/analysis_summary.json\")"
  }'
```

## Step 7: Create Visualizations

Generate comprehensive visualizations:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "# Create visualizations\nimport pandas as pd\nimport matplotlib.pyplot as plt\nimport seaborn as sns\nimport numpy as np\nfrom datetime import datetime\nimport warnings\nwarnings.filterwarnings(\"ignore\")\n\n# Set style for better plots\nplt.style.use(\"seaborn-v0_8\")\nsns.set_palette(\"husl\")\n\n# Load data\ndf = pd.read_csv(\"/workspace/sales_data_cleaned.csv\")\ndf[\"date\"] = pd.to_datetime(df[\"date\"])\ndf[\"is_weekend\"] = df[\"is_weekend\"].astype(bool)\n\nprint(\"Creating visualizations...\")\n\n# Create figure with subplots\nfig = plt.figure(figsize=(20, 24))\n\n# 1. Daily revenue trend\nax1 = plt.subplot(4, 2, 1)\ndaily_revenue = df.groupby(\"date\")[\"revenue\"].sum()\ndaily_revenue.plot(ax=ax1, linewidth=1.5, color=\"blue\", alpha=0.7)\n# Add 7-day moving average\ndaily_revenue.rolling(window=7).mean().plot(ax=ax1, linewidth=2, color=\"red\", label=\"7-day MA\")\nax1.set_title(\"Daily Revenue Trend with 7-day Moving Average\", fontsize=14, fontweight=\"bold\")\nax1.set_xlabel(\"Date\")\nax1.set_ylabel(\"Revenue ($)\")\nax1.legend()\nax1.grid(True, alpha=0.3)\n\n# 2. Revenue by category\nax2 = plt.subplot(4, 2, 2)\ncategory_revenue = df.groupby(\"category\")[\"revenue\"].sum().sort_values(ascending=True)\ncategory_revenue.plot(kind=\"barh\", ax=ax2, color=\"skyblue\")\nax2.set_title(\"Total Revenue by Category\", fontsize=14, fontweight=\"bold\")\nax2.set_xlabel(\"Revenue ($)\")\nfor i, v in enumerate(category_revenue.values):\n    ax2.text(v + 1000, i, f\"${v:,.0f}\", va=\"center\")\n\n# 3. Seasonal analysis\nax3 = plt.subplot(4, 2, 3)\nseasonal_data = df.groupby(\"season\")[\"revenue\"].sum().reindex([\"Winter\", \"Spring\", \"Summer\", \"Fall\"])\nseasonal_data.plot(kind=\"bar\", ax=ax3, color=[\"lightblue\", \"lightgreen\", \"orange\", \"brown\"])\nax3.set_title(\"Revenue by Season\", fontsize=14, fontweight=\"bold\")\nax3.set_ylabel(\"Revenue ($)\")\nax3.set_xticklabels(seasonal_data.index, rotation=45)\nfor i, v in enumerate(seasonal_data.values):\n    ax3.text(i, v + 5000, f\"${v:,.0f}\", ha=\"center\", va=\"bottom\")\n\n# 4. Day of week analysis\nax4 = plt.subplot(4, 2, 4)\nday_order = [\"Monday\", \"Tuesday\", \"Wednesday\", \"Thursday\", \"Friday\", \"Saturday\", \"Sunday\"]\nweekly_data = df.groupby(\"day_name\")[\"revenue\"].sum().reindex(day_order)\ncolors = [\"lightcoral\" if day in [\"Saturday\", \"Sunday\"] else \"lightblue\" for day in day_order]\nweekly_data.plot(kind=\"bar\", ax=ax4, color=colors)\nax4.set_title(\"Revenue by Day of Week\", fontsize=14, fontweight=\"bold\")\nax4.set_ylabel(\"Revenue ($)\")\nax4.set_xticklabels(day_order, rotation=45)\n\n# 5. Regional performance\nax5 = plt.subplot(4, 2, 5)\nregional_data = df.groupby(\"region\")[\"revenue\"].sum()\nwedges, texts, autotexts = ax5.pie(regional_data.values, labels=regional_data.index, autopct=\"%1.1f%%\", startangle=90)\nax5.set_title(\"Revenue Distribution by Region\", fontsize=14, fontweight=\"bold\")\n\n# 6. Price vs Quantity scatter\nax6 = plt.subplot(4, 2, 6)\n# Sample data for better visualization\nsample_df = df.sample(n=min(1000, len(df)))\nscatter = ax6.scatter(sample_df[\"price\"], sample_df[\"quantity\"], \n                     c=sample_df[\"revenue\"], cmap=\"viridis\", alpha=0.6, s=30)\nax6.set_xlabel(\"Price ($)\")\nax6.set_ylabel(\"Quantity\")\nax6.set_title(\"Price vs Quantity (colored by Revenue)\", fontsize=14, fontweight=\"bold\")\nplt.colorbar(scatter, ax=ax6, label=\"Revenue ($)\")\n\n# 7. Age group analysis\nax7 = plt.subplot(4, 2, 7)\nage_data = df.groupby(\"age_group\")[\"revenue\"].sum()\nage_order = [\"18-25\", \"26-35\", \"36-45\", \"46-55\", \"56+\"]\nage_data = age_data.reindex(age_order)\nage_data.plot(kind=\"bar\", ax=ax7, color=\"lightseagreen\")\nax7.set_title(\"Revenue by Age Group\", fontsize=14, fontweight=\"bold\")\nax7.set_ylabel(\"Revenue ($)\")\nax7.set_xticklabels(age_order, rotation=45)\n\n# 8. Monthly trend with seasonal decomposition\nax8 = plt.subplot(4, 2, 8)\nmonthly_revenue = df.groupby([\"year\", \"month\"])[\"revenue\"].sum().reset_index()\nmonthly_revenue[\"date\"] = pd.to_datetime(monthly_revenue[[\"year\", \"month\"]].assign(day=1))\nmonthly_revenue.set_index(\"date\")[\"revenue\"].plot(ax=ax8, marker=\"o\", linewidth=2, markersize=6)\nax8.set_title(\"Monthly Revenue Trend\", fontsize=14, fontweight=\"bold\")\nax8.set_xlabel(\"Month\")\nax8.set_ylabel(\"Revenue ($)\")\nax8.grid(True, alpha=0.3)\n\nplt.tight_layout()\nplt.savefig(\"/workspace/sales_analysis_dashboard.png\", dpi=300, bbox_inches=\"tight\")\nprint(\"Dashboard saved to /workspace/sales_analysis_dashboard.png\")\nplt.close()\n\n# Create correlation heatmap\nfig, ax = plt.subplots(figsize=(10, 8))\nnumeric_cols = [\"price\", \"quantity\", \"revenue\", \"month\", \"day_of_week\"]\ncorr_matrix = df[numeric_cols].corr()\nsns.heatmap(corr_matrix, annot=True, cmap=\"coolwarm\", center=0, \n            square=True, ax=ax, cbar_kws={\"shrink\": 0.8})\nax.set_title(\"Correlation Matrix of Numeric Variables\", fontsize=16, fontweight=\"bold\", pad=20)\nplt.tight_layout()\nplt.savefig(\"/workspace/correlation_heatmap.png\", dpi=300, bbox_inches=\"tight\")\nprint(\"Correlation heatmap saved to /workspace/correlation_heatmap.png\")\nplt.close()\n\n# Create box plots for category comparison\nfig, axes = plt.subplots(2, 2, figsize=(15, 12))\n\n# Revenue distribution by category\nsns.boxplot(data=df, x=\"category\", y=\"revenue\", ax=axes[0,0])\naxes[0,0].set_title(\"Revenue Distribution by Category\")\naxes[0,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=45)\n\n# Price distribution by category\nsns.boxplot(data=df, x=\"category\", y=\"price\", ax=axes[0,1])\naxes[0,1].set_title(\"Price Distribution by Category\")\naxes[0,1].set_xticklabels(axes[0,1].get_xticklabels(), rotation=45)\n\n# Revenue by weekend vs weekday\nsns.boxplot(data=df, x=\"is_weekend\", y=\"revenue\", ax=axes[1,0])\naxes[1,0].set_title(\"Revenue: Weekend vs Weekday\")\naxes[1,0].set_xticklabels([\"Weekday\", \"Weekend\"])\n\n# Revenue by season\nsns.boxplot(data=df, x=\"season\", y=\"revenue\", ax=axes[1,1], \n            order=[\"Winter\", \"Spring\", \"Summer\", \"Fall\"])\naxes[1,1].set_title(\"Revenue Distribution by Season\")\n\nplt.tight_layout()\nplt.savefig(\"/workspace/distribution_analysis.png\", dpi=300, bbox_inches=\"tight\")\nprint(\"Distribution analysis saved to /workspace/distribution_analysis.png\")\nplt.close()\n\nprint(\"\\nAll visualizations created successfully!\")\nprint(\"Files saved:\")\nprint(\"- /workspace/sales_analysis_dashboard.png\")\nprint(\"- /workspace/correlation_heatmap.png\")\nprint(\"- /workspace/distribution_analysis.png\")"
  }'
```

## Step 8: Machine Learning Prediction

Apply machine learning for sales forecasting:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "# Machine Learning for Sales Prediction\nimport pandas as pd\nimport numpy as np\nfrom sklearn.model_selection import train_test_split, cross_val_score\nfrom sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor\nfrom sklearn.linear_model import LinearRegression\nfrom sklearn.preprocessing import LabelEncoder\nfrom sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error\nimport matplotlib.pyplot as plt\nimport warnings\nwarnings.filterwarnings(\"ignore\")\n\n# Load and prepare data\ndf = pd.read_csv(\"/workspace/sales_data_cleaned.csv\")\ndf[\"date\"] = pd.to_datetime(df[\"date\"])\ndf[\"is_weekend\"] = df[\"is_weekend\"].astype(bool)\n\nprint(\"=== PREPARING DATA FOR MACHINE LEARNING ===\")\n\n# Create features for ML\nml_df = df.copy()\n\n# Encode categorical variables\nle_category = LabelEncoder()\nle_region = LabelEncoder()\nle_age_group = LabelEncoder()\nle_season = LabelEncoder()\n\nml_df[\"category_encoded\"] = le_category.fit_transform(ml_df[\"category\"])\nml_df[\"region_encoded\"] = le_region.fit_transform(ml_df[\"region\"])\nml_df[\"age_group_encoded\"] = le_age_group.fit_transform(ml_df[\"age_group\"])\nml_df[\"season_encoded\"] = le_season.fit_transform(ml_df[\"season\"])\n\n# Add time-based features\nml_df[\"days_since_start\"] = (ml_df[\"date\"] - ml_df[\"date\"].min()).dt.days\nml_df[\"is_weekend_int\"] = ml_df[\"is_weekend\"].astype(int)\n\n# Select features for prediction\nfeatures = [\n    \"price\", \"quantity\", \"month\", \"day_of_week\", \"quarter\", \"week_of_year\",\n    \"category_encoded\", \"region_encoded\", \"age_group_encoded\", \"season_encoded\",\n    \"days_since_start\", \"is_weekend_int\"\n]\n\nX = ml_df[features]\ny = ml_df[\"revenue\"]\n\nprint(f\"Features selected: {features}\")\nprint(f\"Dataset shape: {X.shape}\")\nprint(f\"Target variable: revenue\")\n\n# Split data\nX_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)\n\nprint(f\"\\nTraining set: {X_train.shape[0]:,} samples\")\nprint(f\"Test set: {X_test.shape[0]:,} samples\")\n\nprint(\"\\n=== TRAINING MODELS ===\")\n\n# Initialize models\nmodels = {\n    \"Linear Regression\": LinearRegression(),\n    \"Random Forest\": RandomForestRegressor(n_estimators=100, random_state=42, n_jobs=-1),\n    \"Gradient Boosting\": GradientBoostingRegressor(n_estimators=100, random_state=42)\n}\n\n# Train and evaluate models\nmodel_results = {}\n\nfor name, model in models.items():\n    print(f\"\\nTraining {name}...\")\n    \n    # Fit model\n    model.fit(X_train, y_train)\n    \n    # Make predictions\n    y_pred_train = model.predict(X_train)\n    y_pred_test = model.predict(X_test)\n    \n    # Calculate metrics\n    train_r2 = r2_score(y_train, y_pred_train)\n    test_r2 = r2_score(y_test, y_pred_test)\n    train_rmse = np.sqrt(mean_squared_error(y_train, y_pred_train))\n    test_rmse = np.sqrt(mean_squared_error(y_test, y_pred_test))\n    test_mae = mean_absolute_error(y_test, y_pred_test)\n    \n    # Cross-validation\n    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring=\"r2\")\n    \n    model_results[name] = {\n        \"train_r2\": train_r2,\n        \"test_r2\": test_r2,\n        \"train_rmse\": train_rmse,\n        \"test_rmse\": test_rmse,\n        \"test_mae\": test_mae,\n        \"cv_mean\": cv_scores.mean(),\n        \"cv_std\": cv_scores.std(),\n        \"model\": model,\n        \"predictions\": y_pred_test\n    }\n    \n    print(f\"  Train R²: {train_r2:.4f}\")\n    print(f\"  Test R²: {test_r2:.4f}\")\n    print(f\"  Test RMSE: ${test_rmse:.2f}\")\n    print(f\"  Test MAE: ${test_mae:.2f}\")\n    print(f\"  CV R² (mean ± std): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\")\n\nprint(\"\\n=== MODEL COMPARISON ===\")\ncomparison_df = pd.DataFrame({\n    name: {\n        \"Test R²\": results[\"test_r2\"],\n        \"Test RMSE\": results[\"test_rmse\"],\n        \"Test MAE\": results[\"test_mae\"],\n        \"CV Mean R²\": results[\"cv_mean\"]\n    }\n    for name, results in model_results.items()\n}).T\n\nprint(comparison_df.round(4))\n\n# Select best model\nbest_model_name = comparison_df[\"Test R²\"].idxmax()\nbest_model = model_results[best_model_name][\"model\"]\nprint(f\"\\nBest model: {best_model_name}\")\n\n# Feature importance for best model\nif hasattr(best_model, \"feature_importances_\"):\n    print(f\"\\n=== FEATURE IMPORTANCE ({best_model_name}) ===\")\n    feature_importance = pd.DataFrame({\n        \"feature\": features,\n        \"importance\": best_model.feature_importances_\n    }).sort_values(\"importance\", ascending=False)\n    \n    print(feature_importance.round(4))\n    \n    # Plot feature importance\n    plt.figure(figsize=(10, 6))\n    plt.barh(feature_importance[\"feature\"], feature_importance[\"importance\"])\n    plt.xlabel(\"Importance\")\n    plt.title(f\"Feature Importance - {best_model_name}\")\n    plt.gca().invert_yaxis()\n    plt.tight_layout()\n    plt.savefig(\"/workspace/feature_importance.png\", dpi=300, bbox_inches=\"tight\")\n    plt.close()\n    print(\"\\nFeature importance plot saved to /workspace/feature_importance.png\")\n\n# Prediction vs Actual plot\nplt.figure(figsize=(10, 8))\ny_pred_best = model_results[best_model_name][\"predictions\"]\nplt.scatter(y_test, y_pred_best, alpha=0.6, s=30)\nplt.plot([y_test.min(), y_test.max()], [y_test.min(), y_test.max()], \"r--\", lw=2)\nplt.xlabel(\"Actual Revenue ($)\")\nplt.ylabel(\"Predicted Revenue ($)\")\nplt.title(f\"Actual vs Predicted Revenue - {best_model_name}\")\nplt.grid(True, alpha=0.3)\n\n# Add R² to plot\nr2_best = model_results[best_model_name][\"test_r2\"]\nplt.text(0.05, 0.95, f\"R² = {r2_best:.4f}\", transform=plt.gca().transAxes, \n         bbox=dict(boxstyle=\"round\", facecolor=\"white\", alpha=0.8))\n\nplt.tight_layout()\nplt.savefig(\"/workspace/prediction_vs_actual.png\", dpi=300, bbox_inches=\"tight\")\nplt.close()\n\nprint(\"\\n=== GENERATING SAMPLE PREDICTIONS ===\")\n\n# Make predictions for new scenarios\nnew_scenarios = pd.DataFrame({\n    \"price\": [25.0, 100.0, 500.0],\n    \"quantity\": [2, 1, 1],\n    \"month\": [6, 11, 3],  # June, November, March\n    \"day_of_week\": [5, 1, 2],  # Saturday, Tuesday, Wednesday\n    \"quarter\": [2, 4, 1],\n    \"week_of_year\": [24, 46, 12],\n    \"category_encoded\": [1, 0, 2],  # Different categories\n    \"region_encoded\": [2, 0, 4],  # Different regions\n    \"age_group_encoded\": [1, 3, 2],  # Different age groups\n    \"season_encoded\": [2, 0, 1],  # Summer, Winter, Spring\n    \"days_since_start\": [180, 320, 90],\n    \"is_weekend_int\": [1, 0, 0]  # Weekend, weekday, weekday\n})\n\npredicted_revenues = best_model.predict(new_scenarios)\n\nprint(\"Sample predictions:\")\nfor i, pred in enumerate(predicted_revenues):\n    print(f\"Scenario {i+1}: Price=${new_scenarios.iloc[i][\"price\"]}, Quantity={new_scenarios.iloc[i][\"quantity\"]} → Predicted Revenue: ${pred:.2f}\")\n\n# Save model results\nresults_summary = {\n    \"best_model\": best_model_name,\n    \"best_model_r2\": float(model_results[best_model_name][\"test_r2\"]),\n    \"best_model_rmse\": float(model_results[best_model_name][\"test_rmse\"]),\n    \"all_models\": {name: {k: float(v) if isinstance(v, np.floating) else v \n                          for k, v in results.items() if k not in [\"model\", \"predictions\"]}\n                   for name, results in model_results.items()}\n}\n\nimport json\nwith open(\"/workspace/ml_results.json\", \"w\") as f:\n    json.dump(results_summary, f, indent=2, default=str)\n\nprint(f\"\\nML results saved to /workspace/ml_results.json\")\nprint(\"Visualization files created:\")\nprint(\"- /workspace/feature_importance.png\")\nprint(\"- /workspace/prediction_vs_actual.png\")\n\nprint(f\"\\n=== SUMMARY ===\")\nprint(f\"Best performing model: {best_model_name}\")\nprint(f\"Test R² Score: {model_results[best_model_name][\"test_r2\"]:.4f}\")\nprint(f\"Mean Absolute Error: ${model_results[best_model_name][\"test_mae\"]:.2f}\")\nprint(\"Model can predict revenue with good accuracy for business planning.\")"
  }'
```

## Step 9: Generate Executive Report

Create a comprehensive executive summary:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "# Generate Executive Report\nimport pandas as pd\nimport json\nfrom datetime import datetime\n\n# Load all analysis results\ndf = pd.read_csv(\"/workspace/sales_data_cleaned.csv\")\ndf[\"date\"] = pd.to_datetime(df[\"date\"])\n\nwith open(\"/workspace/analysis_summary.json\", \"r\") as f:\n    analysis_data = json.load(f)\n    \nwith open(\"/workspace/ml_results.json\", \"r\") as f:\n    ml_data = json.load(f)\n\nprint(\"Generating Executive Report...\")\n\nreport = f\"\"\"\n# SALES ANALYSIS EXECUTIVE REPORT\n**Generated on: {datetime.now().strftime(\"%B %d, %Y\")}**\n\n## EXECUTIVE SUMMARY\n\nThis comprehensive analysis of sales data reveals key insights into business performance,\ncustomer behavior, and revenue patterns across different dimensions.\n\n### KEY METRICS\n- **Total Revenue**: ${analysis_data[\"total_revenue\"]:,.2f}\n- **Total Orders**: {analysis_data[\"total_orders\"]:,}\n- **Average Order Value**: ${analysis_data[\"avg_order_value\"]:.2f}\n- **Analysis Period**: {df[\"date\"].min().strftime(\"%B %d, %Y\")} to {df[\"date\"].max().strftime(\"%B %d, %Y\")}\n\n## PERFORMANCE INSIGHTS\n\n### 1. SEASONAL PERFORMANCE\n- **Best Season**: {analysis_data[\"best_season\"]}\n- Clear seasonal patterns indicate opportunity for targeted campaigns\n- Revenue fluctuates with seasonal demand cycles\n\n### 2. PRODUCT CATEGORY ANALYSIS\n- **Top Category**: {analysis_data[\"best_category\"]}\n- Category performance varies significantly\n- Portfolio diversification shows balanced revenue distribution\n\n### 3. REGIONAL PERFORMANCE\n- **Leading Region**: {analysis_data[\"best_region\"]}\n- Regional variations suggest market penetration opportunities\n- Geographic expansion potential identified\n\n### 4. CUSTOMER DEMOGRAPHICS\n- Age group analysis reveals target market preferences\n- Customer segmentation opportunities for personalized marketing\n- Demographic-specific product preferences identified\n\n### 5. TEMPORAL PATTERNS\n- Weekend vs Weekday analysis shows significant patterns\n- Daily and monthly trends reveal optimization opportunities\n- Peak selling periods identified for inventory planning\n\n## PREDICTIVE ANALYTICS\n\n### MACHINE LEARNING MODEL PERFORMANCE\n- **Best Model**: {ml_data[\"best_model\"]}\n- **Prediction Accuracy (R²)**: {ml_data[\"best_model_r2\"]:.1%}\n- **Average Prediction Error**: ${ml_data[\"best_model_rmse\"]:.2f}\n\nThe predictive model demonstrates strong performance and can be used for:\n- Revenue forecasting\n- Inventory planning\n- Sales target setting\n- Resource allocation\n\n## STRATEGIC RECOMMENDATIONS\n\n### 1. IMMEDIATE ACTIONS (Next 30 Days)\n- Focus marketing efforts on {analysis_data[\"best_season\"]} season preparation\n- Optimize inventory for {analysis_data[\"best_category\"]} category\n- Develop regional expansion strategy for underperforming areas\n\n### 2. SHORT-TERM INITIATIVES (Next Quarter)\n- Implement customer segmentation strategy based on age groups\n- Launch targeted campaigns for weekend vs weekday patterns\n- Develop seasonal product bundles and promotions\n\n### 3. LONG-TERM STRATEGY (Next Year)\n- Build predictive analytics infrastructure for real-time forecasting\n- Expand product offerings in high-performing categories\n- Invest in regional market development\n\n## DATA QUALITY & METHODOLOGY\n\n### Data Processing\n- **Original Records**: {len(df):,}\n- **Data Cleaning**: Missing values handled, outliers removed\n- **Feature Engineering**: Time-based and categorical features created\n- **Validation**: Statistical significance testing performed\n\n### Analysis Methods\n- Descriptive statistics and exploratory data analysis\n- Statistical hypothesis testing (t-tests, ANOVA)\n- Correlation analysis\n- Machine learning prediction models\n- Cross-validation for model reliability\n\n## RISK FACTORS & LIMITATIONS\n\n- Model predictions based on historical patterns\n- External factors (economy, competition) not included\n- Seasonal variations may affect prediction accuracy\n- Regular model retraining recommended\n\n## CONCLUSION\n\nThe analysis provides a solid foundation for data-driven decision making.\nKey performance indicators show healthy business metrics with clear opportunities\nfor growth and optimization. The predictive models offer reliable forecasting\ncapabilities to support strategic planning.\n\n**Next Steps**: Implement recommended actions and establish regular reporting\ncadence for ongoing performance monitoring.\n\n---\n*Report generated using SandboxRunner Data Science Toolkit*\n*For detailed technical analysis, refer to visualization files and raw data exports*\n\"\"\"\n\n# Save the report\nwith open(\"/workspace/executive_report.md\", \"w\") as f:\n    f.write(report)\n\nprint(\"Executive report saved to /workspace/executive_report.md\")\n\n# Create file inventory\nprint(\"\\n=== FILE INVENTORY ===\")\nprint(\"Data files:\")\nprint(\"- sales_data.csv (original dataset)\")\nprint(\"- sales_data_cleaned.csv (processed dataset)\")\nprint(\"- analysis_summary.json (key metrics)\")\nprint(\"- ml_results.json (machine learning results)\")\nprint(\"\")\nprint(\"Visualizations:\")\nprint(\"- sales_analysis_dashboard.png (comprehensive dashboard)\")\nprint(\"- correlation_heatmap.png (correlation analysis)\")\nprint(\"- distribution_analysis.png (statistical distributions)\")\nprint(\"- feature_importance.png (ML feature importance)\")\nprint(\"- prediction_vs_actual.png (ML model validation)\")\nprint(\"\")\nprint(\"Reports:\")\nprint(\"- executive_report.md (executive summary)\")\n\nprint(\"\\n✅ DATA SCIENCE WORKFLOW COMPLETED SUCCESSFULLY!\")\nprint(\"\\nAll analysis files are ready for download and business review.\")"
  }'
```

## Step 10: Download Results

Download all generated files to your local system:

```bash
# Download all analysis results
files_to_download=(
  "/workspace/sales_data.csv"
  "/workspace/sales_data_cleaned.csv" 
  "/workspace/analysis_summary.json"
  "/workspace/ml_results.json"
  "/workspace/executive_report.md"
  "/workspace/sales_analysis_dashboard.png"
  "/workspace/correlation_heatmap.png"
  "/workspace/distribution_analysis.png"
  "/workspace/feature_importance.png"
  "/workspace/prediction_vs_actual.png"
)

for file in "${files_to_download[@]}"; do
  curl -X POST http://localhost:8080/mcp/tools/download_file \
    -H "Content-Type: application/json" \
    -d "{
      \"sandbox_id\": \"YOUR_SANDBOX_ID\",
      \"path\": \"$file\"
    }" \
    --output "$(basename "$file")"
  echo "Downloaded: $(basename "$file")"
done
```

## Step 11: Clean Up

Clean up the sandbox resources:

```bash
curl -X POST http://localhost:8080/mcp/tools/terminate_sandbox \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID"
  }'
```

## Summary

In this tutorial, you've learned to:

✅ **Set up a complete data science environment** with Python and essential libraries
✅ **Generate and analyze realistic sales data** with comprehensive statistics  
✅ **Perform data cleaning and feature engineering** for better insights
✅ **Create compelling visualizations** including dashboards and plots
✅ **Apply machine learning** for predictive analytics and forecasting
✅ **Generate executive reports** with actionable business insights
✅ **Export all results** for business stakeholders

## Key Takeaways

1. **SandboxRunner provides a complete environment** for data science workflows
2. **Package management is seamless** - just specify what you need
3. **File operations enable complex projects** with multiple assets
4. **Visualization capabilities** support comprehensive reporting
5. **Machine learning integration** enables predictive analytics
6. **Resource isolation** ensures safe, reproducible analysis

## Next Steps

- **Automate workflows**: Create scripts for regular reporting
- **Scale up**: Process larger datasets with increased resources
- **Advanced ML**: Try deep learning frameworks like TensorFlow
- **Real-time analytics**: Integrate with streaming data sources
- **Deployment**: Move models to production environments

This tutorial demonstrates the power of SandboxRunner for complete data science workflows from data ingestion to actionable business insights!